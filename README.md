# KGSL (Kernel Graphics Support Layer) Driver

This repository contains the source code of KGSL driver for the Adreno family
of GPUs. Required to use hardware accelerated OpenGL, compute and Vulkan on
Qualcomm Snapdragon targets.

KGSL is responsible for:
- GPU memory management
- Command submission to GPU
- GPU Power management
- Providing debug and profiling interface to userspace

# Branches

Primary development branch: gfx-kernel.le.0.0

# How-to-Build

This source code can be built using recipe file related to kgsl in meta-qcom
project, which is designed for Qualcomm-based platforms.

Steps for compilation:
- Modify the KGSL driver code as required and generate a corresponding patch
  file.
- Git clone meta-qcom project https://github.com/qualcomm-linux/meta-qcom.git .
- Integrate the patch into the kgsl related recipe file located at
  meta-qcom/recipes-graphics.
- Compile the project. Please refer to the README.md file provided in the
  meta-qcom repository.

# Getting in Contact

Problems specific to the KGSL driver can be reported in the Issues section of
this repository.

# License
This driver is released under the GPL-2.0 license. See LICENSE.txt for details.

