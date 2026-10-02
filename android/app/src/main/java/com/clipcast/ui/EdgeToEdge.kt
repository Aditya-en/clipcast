package com.clipcast.ui

import android.app.Activity
import android.os.Build
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager

/**
 * Framework-only edge-to-edge scaffolding (no libraries).
 *
 * Draws behind the status/navigation bars and display cutout, then pads
 * the content root with the real insets so nothing hides under system bars
 * or the keyboard: status bar, navigation bar, display cutout, and IME are
 * all handled. Call [apply] from the activity's onCreate before setContentView
 * (or any time before first layout), passing the root content view.
 */
object EdgeToEdge {

    fun apply(activity: Activity, root: View) {
        val window = activity.window
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false)
        } else {
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = (
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                    or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            window.attributes = window.attributes.apply {
                layoutInDisplayCutoutMode =
                    WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
            }
        }
        root.setOnApplyWindowInsetsListener { view, insets ->
            val left: Int
            val top: Int
            val right: Int
            val bottom: Int
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val bars = insets.getInsets(
                    WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout()
                )
                val ime = insets.getInsets(WindowInsets.Type.ime())
                left = bars.left
                top = bars.top
                right = bars.right
                // Keyboard overlaps the nav bar area: take whichever is taller.
                bottom = maxOf(bars.bottom, ime.bottom)
            } else {
                @Suppress("DEPRECATION")
                left = insets.systemWindowInsetLeft
                @Suppress("DEPRECATION")
                top = insets.systemWindowInsetTop
                @Suppress("DEPRECATION")
                right = insets.systemWindowInsetRight
                @Suppress("DEPRECATION")
                bottom = insets.systemWindowInsetBottom
            }
            view.setPadding(left, top, right, bottom)
            // Do not consume: children (e.g. nested scrolls) see them too.
            insets
        }
        // The listener runs on the next inset dispatch (attach + focus/IME
        // changes re-dispatch automatically).
        root.requestApplyInsets()
    }
}
