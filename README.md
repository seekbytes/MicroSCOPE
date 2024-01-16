![MicroSCOPE logo](https://github.com/seekbytes/MicroSCOPE/blob/main/utils/MicroSCOPE.jpg?raw=true)

## Project Goal

MicroSCOPE is a software program developed through the [Go](https://go.dev) programming language that allows for the detection of a precise category of malicious software. The program is designed specifically for a class of malicious programs called _ransomware_ whose operation consists of data encryption and ransom demand in order to gain access to the content again.

In particular, MicroSCOPE was developed to be able to support two of the mainly used formats: the PE (_Portable Executable_) format for Windows platforms and ELF (_Executable and Linking Format_) for Unix-based platforms. Through the application of certain heuristics, MicroSCOPE is able to assign a score that corresponds to the level of dangerousness of the file being analyzed. The higher the score, the more similar characteristics the software will exhibit to ransomware that has already been studied. The heuristics have been extrapolated from numerous case studies and will be improved over time.

## Repository Structure
* `analysis`: folder related to the static analysis of the binaries (including the various phases of MicroSCOPE)
* `docs`: folder containing documentation of the MicroSCOPE project.
* `formats`: folder related to the binary file formats (ELF and PE) including constants, checks and parsing of the binary;
* `heuristics`: the actual heuristics.
* `utils`: general utilities

## How it works

The analysis performed by MicroSCOPE has three main steps:
* **data mining**: in-depth analysis of the binary file based on its extension type (for example: whether PE or ELF file), extrapolating strings, functions it uses and any other information potentially useful for predicting program execution;
* **application of heuristics**: based on the information extrapolated from the first stage, heuristics are applied to figure out how the program will behave when executed. At this stage, a score (summation of the various scores of the heuristics) is calculated;
* **outcome determination**: based on the score and above a certain value (called threshold value - user-defined), MicroSCOPE will associate a certain score with malicious behavior;

## How to use it

Download the [latest release](https://github.com/seekbytes/MicroSCOPE/releases) and then run it with the flag `-f` to specify the input file (must be a valid PE or ELF executable).

```
./microscope -f my_executable_ransomware
```