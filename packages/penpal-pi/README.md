# PenPal PI adapter

This PI package lets an operator create an authorized target, paste enumeration evidence into PI, and receive PenPal's masked deterministic suggestions. It includes eight read-only tools and two operator-controlled write tools; it never runs enumeration or uses credentials.

Install the PenPal Python core first, then install this release candidate in PI:

```bash
python3 -m pip install penpal-enum
pi install npm:@yousif_nazhat/penpal-pi@next
```

Set `PENPAL_WORKSPACE` when the workspace is not `penpal-workspace`; set `PENPAL_PYTHON` when Python is not available as `python3`.
