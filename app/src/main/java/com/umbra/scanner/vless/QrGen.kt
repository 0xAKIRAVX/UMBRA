package com.umbra.scanner.vless

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter

object QrGen {

    fun generate(text: String, size: Int = 512): Bitmap? {
        if (text.isEmpty()) return null
        return try {
            val hints = mapOf(
                EncodeHintType.CHARACTER_SET to "UTF-8",
                EncodeHintType.MARGIN to 1,
            )
            val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
            val pixels = IntArray(size * size) { i ->
                if (matrix.get(i % size, i / size)) 0xFF05070A.toInt() else 0xFFF2FFFB.toInt()
            }
            Bitmap.createBitmap(pixels, size, size, Bitmap.Config.ARGB_8888)
        } catch (_: Exception) {
            null
        }
    }
}
