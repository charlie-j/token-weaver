# Instructions

This repository contains the formal analysis of the Token Weaver protocol, as well as a Proof of Concept implementation.

The folder `TEE-models` contains the models, with a dedicated README.

## Using docker

We provide a docker image via dockerhub with the required pre-installed versions of the tools DeepSec and Tamarin (see below for manual installation).

The image can be fetched via:
```
$ docker pull teeanalysis/provers
```

Then, from this repository, or one that has the `TEE-models` inside of it, please run:
```
 $ docker run -it -v $PWD:/opt/case-studies teeanalysis/provers bash
```

This should result in a shell, where the commands `tamarin-prover` and `deepsec` can be executed, and the README inside the `TEE-models` folder can be followed for further results.

## Compiling the tools from source

This folder also contains the file `tamarin-prover.zip` that contains the source files for the Tamarin prover (not yet a fixed version in the main repository), with installation instructions at [https://tamarin-prover.github.io/manual/book/002_installation.html].

The DeepSec tool can be obtained and installed via [https://deepsec-prover.github.io/manual/html/install.html].

## Proof of Concept

The proof of concept for the protocol is inside the PoC/ folder, with a dedicated README
