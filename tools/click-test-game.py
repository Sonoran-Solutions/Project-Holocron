#!/usr/bin/env python3
"""Click a verified SWTOR game window at normalized, screenshot-derived coordinates."""
import argparse
import ctypes as c


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('window', type=lambda value: int(value, 0))
    parser.add_argument('x', type=float)
    parser.add_argument('y', type=float)
    args = parser.parse_args()
    if not (0 <= args.x < 1 and 0 <= args.y < 1):
        parser.error('Coordinates must be fractions inside the observed window.')
    x = c.CDLL('libX11.so.6')
    xt = c.CDLL('libXtst.so.6')
    display_type, window_type = c.c_void_p, c.c_ulong
    x.XOpenDisplay.argtypes, x.XOpenDisplay.restype = [c.c_char_p], display_type
    x.XFetchName.argtypes = [display_type, window_type, c.POINTER(c.c_char_p)]
    x.XInternAtom.argtypes, x.XInternAtom.restype = [display_type, c.c_char_p, c.c_int], c.c_ulong
    x.XGetWindowProperty.argtypes = [display_type, window_type, c.c_ulong, c.c_long, c.c_long, c.c_int, c.c_ulong, c.POINTER(c.c_ulong), c.POINTER(c.c_int), c.POINTER(c.c_ulong), c.POINTER(c.c_ulong), c.POINTER(c.c_void_p)]
    x.XGetGeometry.argtypes = [display_type, window_type, c.POINTER(window_type), c.POINTER(c.c_int), c.POINTER(c.c_int), *([c.POINTER(c.c_uint)] * 4)]
    x.XRaiseWindow.argtypes = [display_type, window_type]
    x.XSetInputFocus.argtypes = [display_type, window_type, c.c_int, c.c_ulong]
    x.XGetInputFocus.argtypes = [display_type, c.POINTER(window_type), c.POINTER(c.c_int)]
    x.XWarpPointer.argtypes = [display_type, window_type, window_type, c.c_int, c.c_int, c.c_uint, c.c_uint, c.c_int, c.c_int]
    x.XSync.argtypes = [display_type, c.c_int]
    x.XFree.argtypes = [c.c_void_p]
    x.XCloseDisplay.argtypes = [display_type]
    xt.XTestFakeButtonEvent.argtypes = [display_type, c.c_uint, c.c_int, c.c_ulong]
    display = x.XOpenDisplay(None)
    if not display:
        raise SystemExit('Cannot open X11 display.')
    try:
        name = c.c_char_p()
        if x.XFetchName(display, args.window, c.byref(name)) and name.value:
            title = name.value.decode('utf-8', errors='replace')
            x.XFree(c.cast(name, c.c_void_p))
        else:
            atom = x.XInternAtom(display, b'_NET_WM_NAME', 1)
            actual, count, remaining = c.c_ulong(), c.c_ulong(), c.c_ulong()
            fmt, data = c.c_int(), c.c_void_p()
            result = x.XGetWindowProperty(display, args.window, atom, 0, 256, 0, 0, c.byref(actual), c.byref(fmt), c.byref(count), c.byref(remaining), c.byref(data))
            if result or not data.value:
                raise SystemExit('Cannot verify the window title; no input sent.')
            try:
                if fmt.value != 8:
                    raise SystemExit('Unexpected window title encoding; no input sent.')
                title = c.string_at(data, count.value).decode('utf-8', errors='replace')
            finally:
                x.XFree(data)
        if 'Star Wars' not in title or 'The Old Republic' not in title:
            raise SystemExit('Refusing input: target is not the observed SWTOR game window.')
        root, px, py = window_type(), c.c_int(), c.c_int()
        width, height, border, depth = (c.c_uint() for _ in range(4))
        if not x.XGetGeometry(display, args.window, c.byref(root), c.byref(px), c.byref(py), c.byref(width), c.byref(height), c.byref(border), c.byref(depth)):
            raise SystemExit('Cannot read window geometry.')
        x.XRaiseWindow(display, args.window)
        x.XSetInputFocus(display, args.window, 2, 0)
        x.XSync(display, 0)
        focus, revert = window_type(), c.c_int()
        x.XGetInputFocus(display, c.byref(focus), c.byref(revert))
        if focus.value != args.window:
            raise SystemExit('Target did not receive focus; no click sent.')
        x.XWarpPointer(display, 0, args.window, 0, 0, 0, 0, int(args.x * width.value), int(args.y * height.value))
        xt.XTestFakeButtonEvent(display, 1, 1, 0)
        xt.XTestFakeButtonEvent(display, 1, 0, 0)
        x.XSync(display, 0)
        print('Clicked the verified SWTOR test window.')
    finally:
        x.XCloseDisplay(display)


if __name__ == '__main__':
    main()
