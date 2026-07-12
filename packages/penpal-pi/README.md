# PenPal PI adapter

This PI package adds PenPal's seven read-only, masked workspace tools to PI.

Install the PenPal Python core first, then install this package locally from a checkout:

```bash
python3 -m pip install penpal-enum
pi install ./packages/penpal-pi
```

Set `PENPAL_WORKSPACE` when the workspace is not `penpal-workspace`; set `PENPAL_PYTHON` when Python is not available as `python3`.

The npm package name is reserved for the public release and remains private until its npm scope is configured.
