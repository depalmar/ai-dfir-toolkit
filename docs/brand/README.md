# Brand files

`sans-logo.svg`, `sans-logo-white.svg` and `sans-logo.png` are the standard SANS
Institute wordmark, in blue and in white for dark backgrounds. SANS supports
this project and cleared the standard logo for it in November 2026.

They are converted from the logo masters SANS supplied for this use
(`SANS-Logos-CornerBand-Blue-CMYK.eps` and `-White-CMYK.eps`), with Ghostscript
and `pdftocairo`; the shapes are unchanged. The masters are CMYK print files,
so the blue here (`#08527D`) is a conversion of the CMYK value, not an RGB
value SANS specified. If SANS supplies an RGB or web version, use its colour. A DFIR-specific SANS logo is in progress; when it is released, replace
these files and keep the names, because the README and the site build
(`artifacts/scripts/build_site.py`) read them by name.

The SANS name and logo are trademarks of SANS Institute. They are not covered
by this repository's CC BY 4.0 or Apache-2.0 licences, so reuse of this
project's content does not carry permission to use them.
