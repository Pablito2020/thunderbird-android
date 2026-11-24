package app.k9mail.feature.account.oauth.data

import java.io.Closeable
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

private const val CALLBACK_TIMEOUT_MILLIS = 300_000
private const val REQUEST_TIMEOUT_SECONDS = 5L
private const val MAX_REQUEST_LINE_BYTES = 8192
private const val MAX_HEADER_BYTES = 16_384
private const val REQUEST_LINE_PARTS = 3

internal class LoopbackOAuthReceiver(private val timeoutMillis: Int = CALLBACK_TIMEOUT_MILLIS) : Closeable {
    private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
    val redirectUri = "http://127.0.0.1:${server.localPort}"

    fun awaitCallback(expectedState: String): String {
        require(expectedState.isNotBlank())
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis.toLong())
        while (true) {
            val remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
            if (remaining <= 0) throw SocketTimeoutException("OAuth callback timed out")
            server.soTimeout = remaining.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
            val target = server.accept().use { socket ->
                try {
                    val requestDeadline = minOf(
                        deadline,
                        System.nanoTime() + TimeUnit.SECONDS.toNanos(REQUEST_TIMEOUT_SECONDS),
                    )
                    val request = readRequestLine(socket, requestDeadline)
                    val callback = request?.let { validate(it, expectedState) }
                    socket.reply(callback != null)
                    callback
                } catch (_: java.io.IOException) {
                    null
                }
            }
            if (target != null) return target
        }
    }

    @Suppress("ReturnCount")
    private fun readRequestLine(socket: Socket, deadline: Long): String? {
        val input = socket.getInputStream()
        fun readByte(): Int {
            val remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
            if (remaining <= 0) throw SocketTimeoutException("OAuth request timed out")
            socket.soTimeout = remaining.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
            return input.read()
        }
        val bytes = ByteArray(MAX_REQUEST_LINE_BYTES)
        for (index in bytes.indices) {
            val byte = readByte()
            if (byte == -1) return null
            if (byte == '\n'.code) {
                val request = String(bytes, 0, index, StandardCharsets.US_ASCII).trimEnd('\r')
                var previousLineEmpty = true
                repeat(MAX_HEADER_BYTES) {
                    when (readByte()) {
                        -1 -> return null

                        '\n'.code -> {
                            if (previousLineEmpty) return request
                            previousLineEmpty = true
                        }

                        '\r'.code -> Unit

                        else -> previousLineEmpty = false
                    }
                }
                return null
            }
            bytes[index] = byte.toByte()
        }
        return null
    }

    @Suppress("ReturnCount")
    private fun validate(request: String, expectedState: String): String? {
        val parts = request.split(' ')
        if (parts.size != REQUEST_LINE_PARTS || parts[0] != "GET" || parts[2] !in listOf("HTTP/1.0", "HTTP/1.1")) {
            return null
        }
        return runCatching {
            val uri = URI(parts[1])
            if (uri.isAbsolute || uri.rawAuthority != null) return null
            if (uri.rawPath != "/" || uri.rawFragment != null) return null
            val query = uri.rawQuery ?: return null
            val params = query.split('&').map { part ->
                URLDecoder.decode(part.substringBefore('='), "UTF-8") to
                    URLDecoder.decode(part.substringAfter('=', ""), "UTF-8")
            }.groupBy({ it.first }, { it.second })
            if (params.values.any { it.size != 1 }) return null
            val state = params["state"]?.singleOrNull() ?: return null
            if (!MessageDigest.isEqual(state.toByteArray(Charsets.UTF_8), expectedState.toByteArray(Charsets.UTF_8))) {
                return null
            }
            val code = params["code"]?.singleOrNull()?.takeIf { it.isNotBlank() }
            val error = params["error"]?.singleOrNull()?.takeIf { it.isNotBlank() }
            if ((code == null) == (error == null)) return null
            if (params.containsKey("code") && params.containsKey("error")) return null
            "$redirectUri${parts[1]}"
        }.getOrNull()
    }

    private fun Socket.reply(success: Boolean) {
        val message = if (success) "Authentication completed. Return to the app." else "Invalid OAuth callback."
        val body = message.toByteArray(StandardCharsets.UTF_8)
        val status = if (success) "200 OK" else "400 Bad Request"
        getOutputStream().apply {
            write(
                (
                    "HTTP/1.1 $status\r\nContent-Type: text/plain; charset=utf-8\r\n" +
                        "Content-Length: ${body.size}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
                    )
                    .toByteArray(StandardCharsets.US_ASCII),
            )
            write(body)
            flush()
        }
    }

    override fun close() = server.close()
}
