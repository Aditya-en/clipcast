package com.clipcast.provider

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.UriMatcher
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File
import java.io.FileNotFoundException

/**
 * Minimal read-only content provider backing clipboard image URIs.
 *
 * Framework-only (no androidx FileProvider dependency): serves files from
 * the app-private `cacheDir/clipboard_images/` directory written by
 * [com.clipcast.util.ClipboardHelper.setImage]. Not exported; receiving
 * apps read through the temporary URI grant attached to the clipboard
 * clip. Only exact `<sha>.<ext>` filenames under the images directory are
 * served — no subdirectories, no path traversal.
 */
class ClipcastImageProvider : ContentProvider() {

    companion object {
        const val AUTHORITY_SUFFIX = ".imageprovider"
        private const val IMAGES = 1

        private val matcher = UriMatcher(UriMatcher.NO_MATCH).apply {
            addURI("*", "images/*", IMAGES)
        }

        fun authorityOf(context: Context): String = context.packageName + AUTHORITY_SUFFIX

        fun uriFor(context: Context, fileName: String): Uri =
            Uri.Builder()
                .scheme("content")
                .authority(authorityOf(context))
                .appendPath("images")
                .appendPath(fileName)
                .build()

        private fun mimeForFile(name: String): String = when (name.substringAfterLast('.', "")) {
            "png" -> "image/png"
            "jpg", "jpeg" -> "image/jpeg"
            "webp" -> "image/webp"
            else -> "application/octet-stream"
        }
    }

    private fun fileFor(uri: Uri): File {
        if (matcher.match(uri) != IMAGES) throw FileNotFoundException("unknown URI: $uri")
        val name = uri.lastPathSegment ?: throw FileNotFoundException("no file: $uri")
        // Exact hex-sha + extension only: rejects traversal and nesting.
        if (!name.matches(Regex("[0-9a-f]{64}\\.[a-z]{2,4}"))) {
            throw FileNotFoundException("bad file name: $name")
        }
        val file = File(context!!.cacheDir, "clipboard_images/$name")
        if (!file.isFile) throw FileNotFoundException("missing: $name")
        return file
    }

    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String? {
        return try {
            val name = uri.lastPathSegment ?: return null
            mimeForFile(name)
        } catch (e: Exception) {
            null
        }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        if (mode != "r" && mode != "rt") throw FileNotFoundException("read-only: $uri")
        return ParcelFileDescriptor.open(fileFor(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? {
        val file = try {
            fileFor(uri)
        } catch (e: Exception) {
            return null
        }
        val cols = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val cursor = MatrixCursor(cols, 1)
        cursor.addRow(cols.map { col ->
            when (col) {
                OpenableColumns.DISPLAY_NAME -> file.name
                OpenableColumns.SIZE -> file.length()
                else -> null
            }
        }.toTypedArray())
        return cursor
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?
    ): Int = 0
}
