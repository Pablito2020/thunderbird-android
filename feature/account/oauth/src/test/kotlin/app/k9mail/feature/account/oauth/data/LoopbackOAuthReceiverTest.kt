package app.k9mail.feature.account.oauth.data

import assertk.assertThat
import assertk.assertions.contains
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertThrows
import org.junit.Test

class LoopbackOAuthReceiverTest {
    @Test
    fun `ignores invalid callbacks and accepts matching state`() {
        val testSubject = LoopbackOAuthReceiver(timeoutMillis = 5_000)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val result = executor.submit<String> { testSubject.awaitCallback("expected") }
            val port = URI(testSubject.redirectUri).port

            assertThat(request(port, "/?state=wrong&code=secret")).contains("400 Bad Request")
            assertThat(request(port, "/?state=expected&state=expected&code=secret")).contains("400 Bad Request")
            assertThat(request(port, "/?state=expected&code=secret&error=denied")).contains("400 Bad Request")
            assertThat(request(port, "/?state=expected&code=secret")).contains("200 OK")
            assertThat(result.get(2, TimeUnit.SECONDS)).contains("state=expected&code=secret")
        } finally {
            testSubject.close()
            executor.shutdownNow()
        }
    }

    @Test
    fun `accepts a valid authorization error`() {
        val testSubject = LoopbackOAuthReceiver(timeoutMillis = 5_000)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val result = executor.submit<String> { testSubject.awaitCallback("expected") }
            val port = URI(testSubject.redirectUri).port

            assertThat(request(port, "/?state=expected&error=access_denied")).contains("200 OK")
            assertThat(result.get(2, TimeUnit.SECONDS)).contains("error=access_denied")
        } finally {
            testSubject.close()
            executor.shutdownNow()
        }
    }

    @Test
    fun `times out if no callback arrives`() {
        LoopbackOAuthReceiver(timeoutMillis = 10).use { testSubject ->
            assertThrows(SocketTimeoutException::class.java) { testSubject.awaitCallback("expected") }
        }
    }

    private fun request(port: Int, target: String): String = Socket("127.0.0.1", port).use { socket ->
        socket.soTimeout = 2_000
        socket.getOutputStream().write("GET $target HTTP/1.1\r\nHost: localhost\r\n\r\n".toByteArray())
        socket.getInputStream().bufferedReader().readText()
    }
}
