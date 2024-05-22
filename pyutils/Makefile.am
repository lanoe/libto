TO_PYTHON = __init__.py config.py methods.py TO_methods.py seclink.py const.py
if WINDOWS_BUILD
TOdir = $(libdir)/site-packages/TO
else
TOdir = $(pythondir)/TO
endif

# Redist archive
# - no config.py
dist-hook:
	cd $(distdir) && rm -rf config.py
