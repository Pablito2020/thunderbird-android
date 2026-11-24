package app.k9mail.feature.account.oauth.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.core.net.toUri
import androidx.lifecycle.lifecycleScope
import app.k9mail.feature.account.oauth.data.LoopbackOAuthReceiver
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.openid.appauth.AuthorizationException
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.CodeVerifierUtil
import net.openid.appauth.ResponseTypeValues
import net.thunderbird.core.common.oauth.OAuthConfiguration

internal class LoopbackOAuthActivity : androidx.activity.ComponentActivity() {
    private var receiver: LoopbackOAuthReceiver? = null
    private var browserLaunched = false
    private var browserPaused = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {
            finish()
        }
    }

    private fun startAuthorization() {
        lifecycleScope.launch {
            try {
                val listener = LoopbackOAuthReceiver().also { receiver = it }
                val request = AuthorizationRequest.Builder(
                    AuthorizationServiceConfiguration(
                        requireNotNull(intent.getStringExtra(AUTHORIZATION_ENDPOINT)).toUri(),
                        requireNotNull(intent.getStringExtra(TOKEN_ENDPOINT)).toUri(),
                    ),
                    requireNotNull(intent.getStringExtra(CLIENT_ID)),
                    ResponseTypeValues.CODE,
                    listener.redirectUri.toUri(),
                ).setScope(requireNotNull(intent.getStringExtra(SCOPES)))
                    .setCodeVerifier(CodeVerifierUtil.generateRandomCodeVerifier())
                    .apply { intent.getStringExtra(LOGIN_HINT)?.takeIf { it.isNotBlank() }?.let(::setLoginHint) }
                    .build()
                browserLaunched = true
                startActivity(Intent(Intent.ACTION_VIEW, request.toUri()))
                val callback = withContext(Dispatchers.IO) { listener.awaitCallback(requireNotNull(request.state)) }
                val callbackUri = callback.toUri()
                val result = if (callbackUri.getQueryParameter("error") != null) {
                    AuthorizationException.fromOAuthRedirect(callbackUri).toIntent()
                } else {
                    AuthorizationResponse.Builder(request).fromUri(callbackUri).build().toIntent()
                }
                setResult(Activity.RESULT_OK, result)
                finish()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    setResult(Activity.RESULT_OK, AuthorizationException.GeneralErrors.NETWORK_ERROR.toIntent())
                    finish()
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        if (browserLaunched) browserPaused = true
    }

    override fun onResume() {
        super.onResume()
        if (isFinishing) return
        if (browserPaused) {
            finish()
        } else if (!browserLaunched) {
            startAuthorization()
        }
    }

    override fun onDestroy() {
        receiver?.close()
        super.onDestroy()
    }

    companion object {
        private const val AUTHORIZATION_ENDPOINT = "authorization_endpoint"
        private const val TOKEN_ENDPOINT = "token_endpoint"
        private const val CLIENT_ID = "client_id"
        private const val SCOPES = "scopes"
        private const val LOGIN_HINT = "login_hint"

        fun createIntent(context: Context, configuration: OAuthConfiguration, emailAddress: String): Intent =
            Intent(context, LoopbackOAuthActivity::class.java).apply {
                putExtra(AUTHORIZATION_ENDPOINT, configuration.authorizationEndpoint)
                putExtra(TOKEN_ENDPOINT, configuration.tokenEndpoint)
                putExtra(CLIENT_ID, configuration.clientId)
                putExtra(SCOPES, configuration.scopes.joinToString(" "))
                putExtra(LOGIN_HINT, emailAddress)
            }
    }
}
