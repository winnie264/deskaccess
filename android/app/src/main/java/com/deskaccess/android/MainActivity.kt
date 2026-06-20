package com.deskaccess.android

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.math.BigInteger
import java.text.DateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private lateinit var inviteInput: EditText
    private lateinit var statusText: TextView
    private lateinit var detailText: TextView
    private lateinit var connectButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildView())
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun buildView(): View {
        val scroll = ScrollView(this)
        scroll.setBackgroundColor(Color.rgb(15, 23, 42))

        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL
        root.setPadding(dp(20), dp(28), dp(20), dp(24))
        scroll.addView(root)

        root.addView(text("DeskAccess", 26, Color.rgb(248, 250, 252), true))
        root.addView(text("Android client", 14, Color.rgb(148, 163, 184), false))

        inviteInput = EditText(this)
        inviteInput.hint = "Paste deskaccess:// invite link"
        inviteInput.setTextColor(Color.rgb(248, 250, 252))
        inviteInput.setHintTextColor(Color.rgb(148, 163, 184))
        inviteInput.setSingleLine(false)
        inviteInput.minLines = 4
        inviteInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        inviteInput.setBackgroundColor(Color.rgb(17, 24, 39))
        inviteInput.setPadding(dp(12), dp(10), dp(12), dp(10))
        root.addView(inviteInput, blockParams(top = 24))

        val actions = LinearLayout(this)
        actions.orientation = LinearLayout.HORIZONTAL
        actions.gravity = Gravity.CENTER_VERTICAL
        root.addView(actions, blockParams(top = 12))

        val paste = button("Paste")
        paste.setOnClickListener { pasteInvite() }
        actions.addView(paste, LinearLayout.LayoutParams(0, dp(44), 1f))

        val parse = button("Check")
        parse.setOnClickListener { checkInvite() }
        actions.addView(parse, LinearLayout.LayoutParams(0, dp(44), 1f).apply { leftMargin = dp(10) })

        connectButton = button("Connect")
        connectButton.isEnabled = false
        connectButton.alpha = 0.55f
        connectButton.setOnClickListener {
            setStatus("Transport bridge not bundled in this APK yet.", true)
        }
        root.addView(connectButton, blockParams(top = 12))

        statusText = text("Waiting for invite link.", 15, Color.rgb(148, 163, 184), false)
        root.addView(statusText, blockParams(top = 24))

        detailText = text("", 14, Color.rgb(203, 213, 225), false)
        root.addView(detailText, blockParams(top = 12))

        return scroll
    }

    private fun handleIntent(intent: Intent?) {
        val data = intent?.data
        if (data != null && isSupportedScheme(data.scheme)) {
            inviteInput.setText(data.toString())
            checkInvite()
        }
    }

    private fun pasteInvite() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = clipboard.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString().orEmpty()
        if (text.isNotBlank()) {
            inviteInput.setText(text.trim())
            checkInvite()
        } else {
            setStatus("Clipboard is empty.", true)
        }
    }

    private fun checkInvite() {
        val raw = inviteInput.text.toString().trim()
        val parsed = InviteToken.parse(raw)
        if (parsed == null) {
            connectButton.isEnabled = false
            connectButton.alpha = 0.55f
            detailText.text = ""
            setStatus("Invalid DeskAccess invite link.", true)
            return
        }
        connectButton.isEnabled = true
        connectButton.alpha = 1f
        setStatus("Invite looks valid.", false)
        detailText.text = parsed.summary()
    }

    private fun setStatus(message: String, error: Boolean) {
        statusText.text = message
        statusText.setTextColor(if (error) Color.rgb(248, 113, 113) else Color.rgb(16, 185, 129))
    }

    private fun text(value: String, sp: Int, color: Int, bold: Boolean): TextView {
        return TextView(this).apply {
            text = value
            textSize = sp.toFloat()
            setTextColor(color)
            if (bold) typeface = android.graphics.Typeface.DEFAULT_BOLD
        }
    }

    private fun button(label: String): Button {
        return Button(this).apply {
            text = label
            isAllCaps = false
        }
    }

    private fun blockParams(top: Int = 0): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(top) }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}

private data class InviteToken(
    val relayMask: Int,
    val expiresAtMillis: Long,
    val mode: Int,
    val protocol: Int,
    val targetPort: Int,
    val hasIrohTicket: Boolean,
    val explicitAddrs: Int
) {
    fun summary(): String {
        val proto = when (protocol) {
            1 -> "VNC"
            2 -> "SSH"
            3 -> "Custom"
            else -> "RDP"
        }
        val modeText = if (mode == 1) "Pairing" else "One-time"
        val port = if (targetPort > 0) targetPort else when (protocol) {
            1 -> 5900
            2 -> 22
            else -> 3389
        }
        val expiry = if (expiresAtMillis > System.currentTimeMillis() + 50L * 365 * 24 * 60 * 60 * 1000) {
            "Until revoked"
        } else {
            DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.getDefault())
                .format(Date(expiresAtMillis))
        }
        val backend = when {
            hasIrohTicket -> "Iroh"
            explicitAddrs > 0 -> "Explicit address"
            relayMask > 0 -> "libp2p relay"
            else -> "Discovery backend"
        }
        return "Mode: $modeText\nProtocol: $proto\nPort: $port\nExpires: $expiry\nBackend: $backend"
    }

    companion object {
        private const val SCHEME = "deskaccess"
        private const val TOKEN_BYTES = 88
        private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        fun parse(raw: String): InviteToken? {
            val uri = try {
                Uri.parse(raw)
            } catch (_: Exception) {
                return null
            }
            if (!isSupportedScheme(uri.scheme)) return null
            val encoded = uri.schemeSpecificPart.removePrefix("//").substringBefore("?").substringBefore("#")
            val bytes = decodeBase58(encoded) ?: return null
            if (bytes.size != TOKEN_BYTES) return null
            val expires = uint32(bytes, 81) * 1000L
            val flags = bytes[85].toInt() and 0xff
            val targetPort = ((bytes[86].toInt() and 0xff) shl 8) or (bytes[87].toInt() and 0xff)
            return InviteToken(
                relayMask = bytes[32].toInt() and 0xff,
                expiresAtMillis = expires,
                mode = flags and 0x0f,
                protocol = (flags ushr 4) and 0x0f,
                targetPort = targetPort,
                hasIrohTicket = !uri.getQueryParameter("iroh").isNullOrBlank(),
                explicitAddrs = uri.getQueryParameters("addr").size
            )
        }

        private fun uint32(bytes: ByteArray, offset: Int): Long {
            return ((bytes[offset].toLong() and 0xff) shl 24) or
                ((bytes[offset + 1].toLong() and 0xff) shl 16) or
                ((bytes[offset + 2].toLong() and 0xff) shl 8) or
                (bytes[offset + 3].toLong() and 0xff)
        }

        private fun decodeBase58(input: String): ByteArray? {
            if (input.isBlank()) return null
            var number = BigInteger.ZERO
            val base = BigInteger.valueOf(58)
            for (char in input) {
                val index = ALPHABET.indexOf(char)
                if (index < 0) return null
                number = number.multiply(base).add(BigInteger.valueOf(index.toLong()))
            }
            val raw = number.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            val leadingZeros = input.takeWhile { it == ALPHABET[0] }.length
            return ByteArray(leadingZeros + raw.size).also {
                System.arraycopy(raw, 0, it, leadingZeros, raw.size)
            }
        }
    }
}

private fun isSupportedScheme(scheme: String?): Boolean {
    return scheme.equals("deskaccess", ignoreCase = true)
}
