# tfimages

This is currently not great but I wanted a way to explore our terraform plans by package and by image.

Generate a plan with `make write-plan && terraform show -json mega-module.tfplan > mega-module.tfplan.json`.

This takes a while but hopefully we'll fix that soon.

Run `tfimages < mega-module.tfplan.json`.

This will pop open a browser that has an index of all the images by package and all the packages by image.
