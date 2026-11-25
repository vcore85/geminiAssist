package io.github.acidefluorhydrique.geminiassist.pcli

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer

object QrCodeHelper {
    private const val MAX_DECODE_DIMENSION = 2048

    fun decodeQrFromBitmap(bitmap: Bitmap): String? {
        val maxDim = maxOf(bitmap.width, bitmap.height)
        val scaledBitmap = if (maxDim > MAX_DECODE_DIMENSION) {
            val scale = MAX_DECODE_DIMENSION.toFloat() / maxDim.toFloat()
            val targetW = (bitmap.width * scale).toInt().coerceAtLeast(1)
            val targetH = (bitmap.height * scale).toInt().coerceAtLeast(1)
            Bitmap.createScaledBitmap(bitmap, targetW, targetH, true)
        } else {
            bitmap
        }

        return try {
            val width = scaledBitmap.width
            val height = scaledBitmap.height
            val pixels = IntArray(width * height)
            scaledBitmap.getPixels(pixels, 0, width, 0, 0, width, height)

            val source = RGBLuminanceSource(width, height, pixels)
            val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
            val hints = mapOf(
                DecodeHintType.TRY_HARDER to true,
                DecodeHintType.CHARACTER_SET to "UTF-8",
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)
            )
            MultiFormatReader().decode(binaryBitmap, hints).text
        } catch (_: Throwable) {
            null
        } finally {
            if (scaledBitmap !== bitmap) {
                scaledBitmap.recycle()
            }
        }
    }
}
