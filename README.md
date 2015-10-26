# Smash4 Tools

This is a collection of tools used to work with game data for Super Smash Bros. for Wii U. Because of the proprietary nature of the content, no data is included and extraction is left as an exercise to the reader.

## extract-patch-data.py
Using the `patchlist` and `resource` files included in updates, extracts the full contents of the `packed` data. Resource parsing is heavily informed by comex's `dtls.py`.

----

Referenced submodules include:

	- comex's smash-stuff, python scripts for parsing some filetypes
	- dantarion's sm4shtools, which parse data for [Master Core](http://opensa.dantarion.com/s4/mastercore3/)
	- crediar's cdecrypt for data decryption