# PenPal PI adapter

This PI package adds PenPal's seven read-only, masked workspace tools to PI.

Install the PenPal Python core first, then install this release candidate in PI:

```bash
python3 -m pip install penpal-enum
pi install npm:@yousif_nazhat/penpal-pi@1.0.0-rc.1
```

Set `PENPAL_WORKSPACE` when the workspace is not `penpal-workspace`; set `PENPAL_PYTHON` when Python is not available as `python3`.
