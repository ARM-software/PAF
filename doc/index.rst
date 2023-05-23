..
  SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023 Arm Limited and/or its
  affiliates <open-source-office@arm.com></text>
  SPDX-License-Identifier: Apache-2.0

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  This file is part of PAF, the Physical Attack Framework.

===============================================================================
PAF, the Physical Attack Framework
===============================================================================

.. contents::
   :depth: 3

Introduction
============

Welcome to the documentation for PAF, the Physical Attack Framework.  PAF is a
suite of tools and libraries to learn about physical attacks, such as fault
injection and side channels, and hopefully help harden code bases against those
threats.

On physical attacks
-------------------

Physical attacks are a specific threat to systems, where systems are considered
in their entirety, i.e. as software + hardware implementations. Those attacks
are taking advantage of physical parameters.

In the case of *side channel attacks*, the aim of the attacker is, by observing
some measurable physical quantities (e.g. time, power consumption, ...), to
guess some details about the execution of program. Those details can then be
used either to reduce the complexity of a brute force attack (for password
guessing for example), or to directly recover a secret (the secret key used in
AES for example)

For *fault injection*, the attacker will physically affect the correct behavior
of the silicon. There are many ways to alter the correct functionality of logic
gates, flip-flops or memory cells: power supply glitching, clock glitching, EM
pulse, laser beam, ... One has to note that physical access is not necessarily
required, `RowHammer <https://en.wikipedia.org/wiki/Row_hammer>`_ and `ClkScrew
<https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-tang.pdf>`_
being two noticeable examples.

It is also worth considering physical attacks from a different point of view:

* *passive* attacks, where an attacker monitors a system's physical quantities
  (time, power consumption, electro-magnetic emissions, ...) to derive
  information leaked by the system's implementation, without trying to affect
  the system's behavior in anyway.

* *active* attacks, where the attacker actively attempts to affect the system
  behavior in some way. This is for example the case with *fault injection*,
  where an attacker, using a voltage or clock glitch for example, will attempt
  to derail the program from its expected execution. But this is also the case
  for some *timing side channel attacks*, like cache attacks, where the
  attacker will change the state of the CPU caches to guess what the program
  under attacks does (by measuring differences in execution time).

Physical attacks will not always lead to the direct exploitation ; they are
often a necessary step though, a prelude to the real exploit, e.g. firmware
extraction with fault injection for offline analysis, or side channel leakages
can reduce the complexity of an attack on cryptographic code, making brute
force attack possible.

On Tarmac traces
----------------

Tarmac traces are detailed traces of a program's execution that are generated
by a number of Arm products, like software models of CPUs (e.g. FastModel). A
detailed description of the Tarmac traces can be found in the documentation of
`tarmac-trace-utilities
<https://github.com/ARM-software/tarmac-trace-utilities/blob/main/doc/index.rst#tarmac-trace-file-format>`__
that PAF relies on for analyzing traces.

On Arm's FastModels
-------------------

Arm's Fast Models are accurate, flexible programmer's view models of Arm IP,
allowing you to develop software such as drivers, firmware, OS and applications
prior to silicon availability. They allow full control over the simulation,
including profiling, debug and trace. A significant portion of PAF relies on
having a FastModel available, please refer to `FasttModel
<https://developer.arm.com/tools-and-software/simulation-models/fast-models>`__
to get yourself one.

Tools flow
==========

This sections intends to introduce a number of concepts used in PAF and be a
walk-thru of PAF's capabilities.

Fault injection
---------------

PAF's fault injection capabilities relies on using an Arm FastModel driven by
the ``run-model.py`` tool.

For example, let's assume that we have a program ``program.elf`` for which we
want to check the resistance against fault injection.

Fault injection is performed in three steps:

1. Get a *reference trace* of a normal execution of ``program.elf`` by running
   it in *simulation* mode with run-model.py_, without any fault:

   .. code-block:: bash

     $ run-model.py -t program.trace program.elf

2. Analyze the Tarmac *reference trace* to produce a *fault campaign* file:
   given a `Fault model`_ and a place of interest for injection (because one is
   interested in attacking a specific part of the program, not the complete
   program), the paf-faulter_ tool will produce a list of all faults to inject
   as well as some more ancillary data useful for the fault injection in a
   so-called `Fault campaign`_ file.

   .. code-block:: bash

     $ paf-faulter --instructionskip \
         --oracle='@(fault_occurred){success};@(crash_detected){crash};return(main){noeffect}' \
         --output=campaign.yml \
         --image=program.elf --functions=checkPIN program.trace

3. Execute again ``program.elf`` with run-model.py_, but this time in fault
   injection mode. This will run the program as many times as there are faults
   in the campaign, and will classify the fault effects according to `Fault
   classification`_. 

   .. code-block:: bash

     $ run-model.py --driver=FaultInjection -c campaign.yml program.elf
     41 faults to inject.
     100%|##############################################| 41/41 [00:07<00:00,  5.23 faults/s]
     41 faults injected: 11 successful, 0 caught, 28 noeffect, 2 crash and 0 undecided

Fault model
~~~~~~~~~~~

Faults are fundamentally taking place at the transistor level, which makes
fault injection simulation at that level of details not so much tractable in
practice. Instead, PAF's fault injection simulation relies on fault models,
which are a high level abstraction of faults' effects. For example, for now PAF
supports:

* *InstructionSkip*: this models the effect of faults for which the
  instruction appears not to be executed.

* *RegisterDefinitionCorruption*: this models the effect of faults that
  appears to corrupt the destination operand of an instruction.

* Many more fault models can easily be implemented, e.g. memory corruption, or
  source operand corruption are on the top of the list

All models are wrong (in some way), because they are abstractions of a more
complex underlying reality, but they remain useful to analyze the behavior of
a piece of code under different scenarios. It's also worth mentioning that
different models can make a program exhibit the same behavior, or said
differently, different fault models can be used to model a similar effect ; for
example, in a sequence of instructions like ``CMP + BNE`` (a comparison flowed
by a conditional branch), the effect of skipping the ``BNE`` can be equally
done with faulting the program status register set by the ``CMP`` instruction.

Fault campaign
~~~~~~~~~~~~~~

A fault campaign is a container with all information needed to perform a
fault injection campaign: information about a program, the fault model used,
and the list of all fault to inject together with the details of how to inject
them.

Fault classification
~~~~~~~~~~~~~~~~~~~~

When analyzing the resistance of a program against fault attacks, it's useful
to classify the faults according to their effects:

* *success*: the fault was injected and had an effect on the behavior of the
  program that can be considered a successful attack.

* *noeffect*: the fault was injected, but did not have a noticeable impact on
  the behavior of the program. This might be true, but this could also be
  because the Oracle_ was not defined precisely enough.

* *crash*: faults do mess-up the code in many ways (e.g. accesses to invalid
  memory, unaligned accesses, ...), which are often capture by exception
  handlers. Note that classifying a fault effect as a crash does not mean the
  fault can not be successful ! It only means that the fault effect will depend
  on how the the exception handlers are setup and will manage the exception.
  The *crash* classification should be used when it is not known what will
  happen exactly, because for example the exception handlers behavior are
  managed by a different team, and further thinking is needed.

* *caught*: this classification is useful when a program has protections
  against fault injections. These protections, on top of passive measures like
  redundancy often come with an active aspect, where the program will change
  and adapt its behavior when it becomes suspicious of a fault injection. In
  the literature, this is often the ``kill_card`` function that gets invoked
  to wipe out all secrets for example. It is useful, when testing the
  resistance of a program to be able to classify the faults that have been
  caught by the protection schemes.

* *notrun*: this classification is for faults which have not been injected.
  It's useful in reports to be able mark them as *notrun*.

* *undecided*: faults can alter the control flow of a program, and knowing
  when to halt the simulation is a hard problem. In some cases, the program
  can still be in the valid control flow (compared to the reference
  execution), but locked in an infinite loop, or may be a few more cycles of
  simulation would have enabled to conclude. This classification usually
  appears when some sort of timeouts set to the simulation have triggered.

Oracle
~~~~~~

The oracle is in charge of classifying the effect of a fault. A fault
classification is attempted at specific events, and involves inspecting the
state of a program. As such, this is an event based process, with some first
order logical formulae referring to program registers and variables. There is
captured in a mini-DSL.

A simplified pseudo-grammar for the Oracle-DSL looks like:

  *classifier* ::= *event* { *classification* }

  *event* ::= *@* (``function``) | *return* (``function``)

  *classification* ::= ``success`` | ``noeffect`` | ``crash`` | ``caught`` | ``notrun`` | ``undecided`` 

The triggering *event* is either a call to or a return from ``function``. In
the full Oracle-DSL, *classification* is a first order formula, which is
simplified here to always return the fault classification.
Multiple classifiers can be added to an oracle.

An example of fault injection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Side channels
-------------

Timing
~~~~~~

When protecting against side channels, one of the first (not so) obvious step
is to harden against timing side channels. A timing side channel exist when
depending on some sensitive input (like a secret), the program will have a
different behavior. The most obvious difference is execution time, i.e. when
program execution differs in time. A desirable goal is thus to ensure the
sensitive part of a program executes in constant-time, that's to say
independent of the sensitive data values.

In this example, we will see how a non-constant time behavior can be found
with PAF. The simplistic ``check`` program below compare pin digits. For the
sake of the example, it is made non constant time in an explicit way, as the
pin comparison exit early as soon as a difference is found:

.. code-block:: bash

  $ cat check.c
  #include <stdio.h>
  
  #define DIGITS 4
  
  char pin[DIGITS] = "1234";
  
  int main(int argc, char \*argv[]) {
      if (argc > 1) {
          for (unsigned i = 0; i < DIGITS; i++)
              if (argv[1][i] != pin[i])
                  return 0;
          return 1;
      }
  
      return 0;
  }

The program is then compiled, then simulated with run-model.py_ with different
input PIN values. We have used here two well chosen value for the sake of
illustration, but in practice one could be using fuzzing for example to explore
a number of other values:

.. code-block:: bash

  $ arm-none-eabi-gcc -o check.elf -O2 -Wall -mthumb -mcpu=cortex-m3 check.c --specs=rdimon.specs
  $ run-model.py -u FVP_MPS2_M3.yml -s -t check1.trace check.elf 1344
  $ run-model.py -u FVP_MPS2_M3.yml -s -t check2.trace check.elf 1244

Now that we have a number of execution traces captures with different inputs,
these can be compared by paf-constanttime_, a utility that will report
divergences in Tarmac traces:

.. code-block:: bash

  $ paf-constanttime --image=check.elf main check1.trace check2.trace
  index file check1.trace.index is older than trace file check1.trace; rebuilding it
  index file check2.trace.index is older than trace file check2.trace; rebuilding it
  Running analysis on trace 'check1.trace'
   - Building reference trace from main instance at time : 698 to 715
  698     X       CMP r0,#1
  699     -       BLE {pc}+0x1a
  700     X       LDR r1,[r1,#4]   R4(0x1a066)@0x106ffff8
  701     X       LDR r2,{pc}+0x1e         R4(0x1a164)@0x8050
  702     X       SUBS r3,r1,#1
  703     X       ADDS r1,#3
  704     X       LDRB r12,[r3,#1]!        R1(0x31)@0x1a066
  705     X       LDRB r0,[r2],#1  R1(0x31)@0x1a164
  706     X       CMP r12,r0
  707     -       BNE {pc}+0xa
  708     X       CMP r3,r1
  709     X       BNE {pc}-0xe
  710     X       LDRB r12,[r3,#1]!        R1(0x33)@0x1a067
  711     X       LDRB r0,[r2],#1  R1(0x32)@0x1a165
  712     X       CMP r12,r0
  713     X       BNE {pc}+0xa
  714     X       MOVS r0,#0
  715     X       BX lr
  Running analysis on trace 'check2.trace'
   - Comparing reference to instance at time : 698 to 721
     o Time:713 Executed:1 PC:0x8042 ISet:1 Width:16 Instruction:0xd103 BNE {pc}+0xa (reference)
       Time:713 Executed:0 PC:0x8042 ISet:1 Width:16 Instruction:0xd103 BNE {pc}+0xa
     o Time:714 Executed:1 PC:0x804c ISet:1 Width:16 Instruction:0x2000 MOVS r0,#0 (reference)
       Time:714 Executed:1 PC:0x8044 ISet:1 Width:16 Instruction:0x428b CMP r3,r1

In this case, ``paf-constanttime`` has found 2 divergences: 

* at time 713, depending on the input value, the instruction at PC: 0x8042 was
  executed (or not).

* at time 714, thus following the difference in control flow, 2 different
  instructions are executed.

Power / EM
~~~~~~~~~~

Another source of side channel leakage are the system's power consumption and
its electro-magnetic emissions, because the power consumption (and EM emission)
depends on the instruction being executed as well as the data manipulated by
this instruction. By recording power trace of the system executing with
different data, and analyzing their behavior with statistical analysis tools, he
might be able to derive some useful information, if not directly a secret
information. Those type of attacks require manipulating a large amount of
tabular recorded data, so PAF has not re-created the wheel and reuses a
commonly used container for storing those traces: `NumPy <https://numpy.org/>`_
arrays. Reusing this standard storage has additional benefits:

* NumPy arrays can be used natively in other environments than PAF, e.g.
  python or `Jupiter <https://jupyter.org/>`_ notebooks,

* NumPy arrays can be exported by power trace acquisition environment,
  including `NewAE <https://www.newae.com/>_` ChipWhisperer environment,

making it a de-facto must-use container.

PAF's side channel analysis tools are however written in C++, so PAF's include
a class, ``NPArray`` to manipulate simple 1D or 2D arrays. More complex data
structures supported by the NumPy format are not supported. As a consequence,
different types of data are stored in different files ; for example the power
acquisition trace intrinsically has floating point values and will be stored as
such, whereas the input values that were used to generate that trace are often
integer values.

PAF makes some assumptions on how data are stored in the numpy files. PAF
expects the row major order to be used. For example, let's assume that you want
to use 100 traces of 20 samples each, and that each trace was using 4 data,
then you should have 100 x 20 numpy array of ``doubles`` (in file say
``traces.npy``) and another 100 x 4 numpy array of ``uint32_t`` (in file say
``inputs.npy``).

Tools usage
===========

Tarmac trace utilities tools
----------------------------

PAF relies on `tarmac-trace-utilities
<https://github.com/ARM-software/tarmac-trace-utilities>`_ for all its
functionality related to tarmac trace analysis. As such, it will give access to
all tools provided by the Tarmac Trace Utilities:

* ``tarmac-browser``: a terminal-based interactive browser for trace files.

* ``tarmac-callinfo``: reports on calls to a specific function or address.

* ``tarmac-calltree``: displays the full hierarchy of function calls
  identified in the trace.

* ``tarmac-flamegraph``: writes out profiling data derived from the trace
  file, in a format suitable for use with the 'FlameGraph' tools that can be
  found at https://github.com/brendangregg/FlameGraph.

* ``tarmac-gui-browser``: is a GUI-based interactive browser for trace files.

* ``tarmac-profile``: prints out simple profiling data derived from the trace
  file, showing the amount of time spent in every function.

* ``tarmac-vcd``: translates the trace file into
  `Value Change Dump <https://en.wikipedia.org/wiki/Value_change_dump>`_.

For more detailled information on those tools, please refer to their `documentation
<https://github.com/ARM-software/tarmac-trace-utilities/blob/main/doc/index.rst>`_.


PAF's generic tools
-------------------

``run-model.py``
~~~~~~~~~~~~~~~~

``run-model.py`` is a driver for Arm's FastModel. It uses the FastModel Iris
interface to control the simulation and make it do more than just running some
code. It assumes that a FastModel is installed, and it expects the environment
variable ``IRIS_HOME`` to be set and point to where the Iris python module can
be found.

The command line syntax looks like:
  ``run-model.py`` [ *options* ] *elf_image* [ *image_args+* ]

``run-model.py`` drives the Arm's FastModel simulation in different ways
depending on the driver it has been invoked with:

* plain simulation mode: this is the standard operating mode of the FastModel.
  This is the ``IrisDriver`` and is the default driver.

* fault injection mode: in this mode, ``run-model.py`` will run the simulation
  as many times as there are faults in the user supplied fault campaign file,
  and at each run inject a fault and try to classify it according to the
  oracle.

* check-point mode: in this mode, ``run-model.py`` will stop the simulation at
  some user specified point and perform a number of checks (register content,
  memory values, ...). It's essentially equivalent to setting a breaking in a
  debugger and inspecting the program state.

* data-override mode: in this mode, ``run-model.py`` will pause the simulation
  at a user specified location (typically a function entry), and will
  override data in memory with user provided data. The simulation will then
  resume its course. This is useful for checking some hypothesis, or using the
  same binary, without recompilation for example.

Arm's FastModel are versatile and can represent lots of different systems, with
variant configurations and thus options. ``run-model.py`` can make use of a
so-called *user session file* which will ease the FastModel run configuration.
A typical session file will look like:

.. code-block:: yaml

  Model: "/opt/FastModels/11.12/FVP_MPS2_Cortex-M3_CC312/models/Linux64_GCC-6.4/FVP_MPS2_Cortex-M3_CC312"
  PluginsDir: "/opt/FastModels/11.12/FastModelsPortfolio_11.12/plugins/Linux64_GCC-6.4"
  Verbosity:
    - {Option: false, Name: "fvp_mps2.telnetterminal0.quiet", Value: 1}
    - {Option: false, Name: "fvp_mps2.telnetterminal1.quiet", Value: 1}
    - {Option: false, Name: "fvp_mps2.telnetterminal2.quiet", Value: 1}
  GUI:
    - {Option: false, Name: "fvp_mps2.mps2_visualisation.disable-visualisation", Value: 1}
  SemiHosting:
    Enable: {Name: "armcortexm3ct.semihosting-enable", Value: 1}
    CmdLine: {Name: "armcortexm3ct.semihosting-cmd_line", Value: ""}

The ``Model`` and ``PluginsDir`` fields have to be adapted to your specific
installation of the Arm FastModel. ``Model`` points to where the FastModel
executable has been installed, whereas ``PluginsDir`` points to where plugins,
like the one needed for recording Tarmac traces can be found (e.g
``TarmacTrace.so`` in a linux installation).

The ``Verbosity``, ``GUI`` and ``SemiHosting`` dictionaries are used by
``run-model.py`` to perform the right actions on the model when the verbosity
is increased (``-v``), or when the GUI is requested (``-gui``), or when
semi-hosting is used (``--enable-semihosting``). They contain option polarity,
and the ``Name`` field correspond to a parameter in the Arm FastModel.

``run-model.py`` positional arguments are:

``elf_image``
  The ELF image to load.

``image_args``
  The ELF image arguments.

``run-model.py`` supports the following optional arguments:

``-h`` or ``--help``
  Show this help message and exit

``-v`` or ``--verbose``
  Be more verbose, may be specified multiple times.

``-V`` or ``--version``
  Print the version number of this tool.

``-s`` or ``--enable-semihosting``
  Use semihosting for passing arguments and getting the exit value

``-g`` or ``--enable-remote-gdb``
  Enable the remote debug server. You can then point your debugger to
  127.0.0.1:31627 ('gdb-remote 127.0.0.1:31627' in LLDB)

``-l SECONDS`` or ``--cpu-limit SECONDS``
  Set a time limit on the host cpu to the simulation (default:0).

``-t [TRACE]`` or ``--enable-trace [TRACE]``
  Trace instructions to file TRACE if provided, elf_image.trace otherwise

``-d {IrisDriver,FaultInjection,CheckPoint,DataOverrider}`` or ``--driver {IrisDriver,FaultInjection,CheckPoint,DataOverrider}``
  Set the simulation driver to use

``-c CampaignFile`` or ``--driver-cfg CampaignFile``
  simulation driver configuration to use (a.k.a fault injection campaign)

``-f FaultIds`` or ``--fault-ids FaultIds``
  A comma separated list of fault Ids or Ids range to run (from the fault
  injection campaign)

``-j NUM`` or ``--jobs NUM``
  Number of fault injection jobs to run in parallel (default: 1)

``--hard-psr-fault``
  With the CorruptRegDef model, fault the full PSR instead of just the CC

``--reg-fault-value {reset,one,set}``
  With the register fault models, reset the register, set it to 1 or set it
  to all 1s

``--gui``
  Enable the fancy gui from the FVP

``--override-when-entering FUNC``
  override data when entering function FUNC

``--override-symbol-with SYMBOL:BYTESTRING[,SYMBOL:BYTESTRING]``
  Override SYMBOL with bytes from BYTESTRING

``--ignore-return-value``
  Ignore the return value from semihosting or from the simulator

``--dry-run``
  Don't actually run the simulator, just print the command line that would be
  used to run it

``-u SessionCfgFile`` or ``--user-cfg SessionCfgFile``
  Defines the model meaningful options for you in your environment

``--stat``
  Print run statistics on simulation exit

``--iris-port PORT``
  Set the base iris port number to use (default:7100)

``--start-address ADDRESS``
  Set the PC at ADDRESS at the start of simulation

``--exit-address ADDRESSES``
  Stop and exit simulation when PC matches any address in ADDRESSES.
  ADDRESSES is interpreted as a comma separated list of symbol names or
  addresses

``--data binary``
  Data loading and placement

Here are a few example usage of ``run-model.py``. In the first example, one
simply executes the canonical "Hello World !" on a Cortex-M3, using
semi-hosting:

.. code-block:: bash

   $ cat Hello.c
   #include <stdio.h>
   
   int main(int argc, char *argv[]) {
     const char *someone = "World";
     if (argc>1)
       someone = argv[1];
   
     printf("Hello, %s !", someone);
   
     return 0;
   }

   $ arm-none-eabi-gcc -o Hello.elf -O2 -Wall -mthumb -mcpu=cortex-m3 Hello.c --specs=rdimon.specs
   $ run-model.py -u FVP_MPS2_M3.yml -s Hello.elf
   $ cat Hello.elf.stdout
   Hello, World !

But as semi-hosting is used, one can also pass parameters to the program.

.. code-block:: bash

   $ run-model.py -u FVP_MPS2_M3.yml -s Hello.elf Bob
   $ cat Hello.elf.stdout
   Hello, Bob !

One could also record a Tarmac trace with:

.. code-block:: bash

   $ run-model.py -u FVP_MPS2_M3.yml -s -t Hello.trace Hello.elf Bob
   $ head Hello.trace
   0 clk E DebugEvent_HaltingDebugState 00000000
   0 clk R cpsr 01000000
   0 clk SIGNAL: SIGNAL=poreset STATE=N
   0 clk SIGNAL: SIGNAL=poreset STATE=N
   0 clk E 000080ac 00000001 CoreEvent_RESET
   0 clk R r13_main 464c457c
   0 clk R MSP 464c457c
   1 clk IT (1) 000080ac 2016 T thread : MOVS     r0,#0x16
   1 clk R r0 00000016
   1 clk R cpsr 01000000

PAF's fault injection specific tools
------------------------------------

``campaign.py``
~~~~~~~~~~~~~~~

``campaign.py`` is a utility script to perform a number of actions on campaign
files, from displaying a summary to modifying some fields in an automated way.

The command line syntax looks like:
  ``campaign.py`` [ *-h* ] [ *-v* ] [ *-V* ] [ *--offset-fault-time-by* *OFFSET* ] [ *--offset-fault-address-by* *OFFSET* ] [ *--summary* ] [ *--dry-run* ] *CAMPAIGN_FILE* [*CAMPAIGN_FILE*\ ...]

where *CAMPAIGN_FILE* denotes a campaign file to process.

The available actions to perform on the *CAMPAIGN_FILEs* are:

``--offset-fault-time-by OFFSET``
  Offset all fault time by OFFSET

``--offset-fault-address-by OFFSET``
  Offset all fault addresses by OFFSET

``--summary``
  Display a summary of the campaign results

``campaign.py`` supports the following optional arguments:

``-h`` or ``--help``
  Show this help message and exit

``-v`` or ``--verbose``
  Be more verbose, may be specified multiple times.

``-V`` or ``--version``
  Print the version number of this tool.

``--dry-run``
  Perform the action, but don't save the file and dump it for visual inspection.

As an example, one can get a summary report of a fault injection campaign with:

.. code-block:: bash

   $ campaign.py --summary verifyPIN-O2.is.yml.results
   41 faults: 0 caught, 2 crash, 28 noeffect, 0 notrun, 11 success, 0 undecided

which let us know that 41 faults were injected, that 11 led to a successful
attack, that 2 crashed somehow the program and the 28 had no noticeable effect.

``paf-faulter``
~~~~~~~~~~~~~~~

Given a fault model (e.g. instruction skip), ``paf-faulter`` will analyze a
reference instruction trace in the Tarmac format and produce a fault injection
campaign file.

The command line syntax looks like:
  ``paf-faulter`` [ *options* ] *TRACEFILE*

The following options are recognized:

``--image=IMAGEFILE``
  Image file name

``--only-index``
  Generate index and do nothing else

``--force-index``
  Regenerate index unconditionally

``--no-index``
  Do not regenerate index

``--li``
  Assume trace is from a little-endian platform

``--bi``
  Assume trace is from a big-endian platform

``-v`` or ``--verbose``
  Make tool more verbose

``-q`` or ``--quiet``
  Make tool quiet

``--show-progress-meter``
  Force display of the progress meter

``--index=INDEXFILE``
  Index file name

``--instructionskip``
  Select InstructionSkip faultModel

``--corruptregdef``
  Select CorruptRegDef faultModel

``--output=CAMPAIGNFILE``
  Campaign file name

``--oracle=ORACLESPEC``
  Oracle specification

``--window-labels=WINDOW,LABEL[,LABEL+]``
  A pair of labels that delimit the region where to inject faults.

``--labels-pair=START_LABEL,END_LABEL``
  A pair of labels that delimit the region where to inject faults.

``--flat-functions=FUNCTION[,FUNCTION]+``
  A comma separated list of function names where to inject faults into (excluding their call-tree)

``--functions=FUNCTION[,FUNCTION]+``
  A comma separated list of function names where to inject faults into (including their call-tree)

``--exclude-functions=FUNCTION[,FUNCTION]+``
  A comma separated list of function names to skip for fault injection

An example usage, extracted from the ``tests/`` directory looks like:

.. code-block:: bash

   $ run-model.py -u FVP_MPS2_M3.yml -s --ignore-return-value --iris-port 7354 \
                  -t verifyPIN-O2.elf.trace verifyPIN-O2.elf 1244
   $ paf-faulter --instructionskip \
       --oracle='@(fault_occurred){success};@(crash_detected){crash};return(main){noeffect}' \
       --output=verifyPIN-O2.is.yml \
       --image=verifyPIN-O2.elf --functions=verifyPIN@0 verifyPIN-O2.elf.trace
   index file verifyPIN-O2.elf.trace.index is older than trace file verifyPIN-O2.elf.trace; rebuilding it
   Inject faults into (1) functions: verifyPIN@0
   Excluded functions (0): -
   Will inject faults on 'verifyPIN@0' : t:2944 l:7112 pc=0x8249 - t:2984 l:7214 pc=0x827b
   Injecting faults on range t:2944 l:7112 pc=0x8249 - t:2984 l:7214 pc=0x827b
   $ cat verifyPIN-O2.is.yml
   Image: "verifyPIN-O2.elf"
   ReferenceTrace: "verifyPIN-O2.elf.trace"
   MaxTraceTime: 4235
   ProgramEntryAddress: 0x815c
   ProgramEndAddress: 0x10aca
   FaultModel: "InstructionSkip"
   FunctionInfo:
     - { Name: "verifyPIN@0", StartTime: 2944, EndTime: 2984, StartAddress: 0x8248, ...
   Oracle:
     - { Pc: 0x8010, Classification: [["success",[]]]}
     - { Pc: 0x8280, Classification: [["crash",[]]]}
     - { Pc: 0x80de, Classification: [["noeffect",[]]]}
   Campaign:
     - { Id: 0, Time: 2944, Address: 0x8248, Instruction: 0xb530, Width: 16, ...
     - { Id: 1, Time: 2945, Address: 0x824a, Instruction: 0x6815, Width: 16, ...
     ...

A reference trace for program ``verifyPIN-O2.elf`` invoked with user pin
argument ``1244`` is first recorded. The ``paf-faulter`` is invoked, with the
instruction skip fault model and will analyze the trace and produce a fault
campaign for the very first execution of function ``verifyPIN``.

PAF's side channel specific tools
---------------------------------

``paf-calibration``
~~~~~~~~~~~~~~~~~~~

``paf-calibration`` is a small utility to test if the ADC used for acquiring
the power consumption of a device has correct settings (gain, ...).

The command line syntax looks like:
  ``paf-calibration`` *file.npy* [ *file.npy* ]

``paf-calibration`` will accumulate statistics over the NPY files provided on
the command line and then report them. It will report if some calibration is
required. At the time of writing, this is hard wired for captures done on a
chipwhisperer board but can easily be improved to support other ADCs..

Example usage:

.. code-block:: bash

  $ paf-calibration traces.npy
  Overall min sample value: -0.255859 (3)
  Overall max sample value: 0.220703 (2)

As the expected range of values should be in [-0.5 .. 0.5(, the ADC settings
could benefit from a bit of gain to use the full available range.

``paf-constanttime``
~~~~~~~~~~~~~~~~~~~~

``paf-constanttime`` is a utility that compare parts of traces, typically
functions, and look for divergences, in control-flow, in execution or in memory
accesses. In some way, this is a ``diff`` tool, but it takes into account the
Tarmac trace format and the structure of the executed code.

The command line syntax looks like:
   ``paf-constanttime`` [ *options* ] *FUNCTION* *TRACEFILE*\ ...

The following options are recognized:

``--ignore-conditional-execution-differences``
  Ignore differences in conditional execution

``--ignore-memory-access-differences``
  Ignore differences in memory accesses

``--image=IMAGEFILE``
  Image file name

``--only-index``
  Generate index and do nothing else

``--force-index``
  Regenerate index unconditionally

``--no-index``
  Do not regenerate index

``--li``
  Assume trace is from a little-endian platform

``--bi``
  Assume trace is from a big-endian platform

``-v`` or ``--verbose``
  Make tool more verbose

``-q`` or ``--quiet``
  Make tool quiet

``--show-progress-meter``
  Force display of the progress meter

As an example usage, if we get back to our walk-thru on timing side channels (see `Timing`_):

.. code-block:: bash

   $ paf-constanttime --image=check.elf main check1.trace check2.trace
   index file check1.trace.index is older than trace file check1.trace; rebuilding it
   index file check2.trace.index is older than trace file check2.trace; rebuilding it
   Running analysis on trace 'check1.trace'
    - Building reference trace from main instance at time : 698 to 715
   698     X       CMP r0,#1
   699     -       BLE {pc}+0x1a
   700     X       LDR r1,[r1,#4]   R4(0x1a066)@0x106ffff8
   701     X       LDR r2,{pc}+0x1e         R4(0x1a164)@0x8050
   702     X       SUBS r3,r1,#1
   703     X       ADDS r1,#3
   704     X       LDRB r12,[r3,#1]!        R1(0x31)@0x1a066
   705     X       LDRB r0,[r2],#1  R1(0x31)@0x1a164
   706     X       CMP r12,r0
   707     -       BNE {pc}+0xa
   708     X       CMP r3,r1
   709     X       BNE {pc}-0xe
   710     X       LDRB r12,[r3,#1]!        R1(0x33)@0x1a067
   711     X       LDRB r0,[r2],#1  R1(0x32)@0x1a165
   712     X       CMP r12,r0
   713     X       BNE {pc}+0xa
   714     X       MOVS r0,#0
   715     X       BX lr
   Running analysis on trace 'check2.trace'
    - Comparing reference to instance at time : 698 to 721
      o Time:713 Executed:1 PC:0x8042 ISet:1 Width:16 Instruction:0xd103 BNE {pc}+0xa (reference)
        Time:713 Executed:0 PC:0x8042 ISet:1 Width:16 Instruction:0xd103 BNE {pc}+0xa
      o Time:714 Executed:1 PC:0x804c ISet:1 Width:16 Instruction:0x2000 MOVS r0,#0 (reference)
        Time:714 Executed:1 PC:0x8044 ISet:1 Width:16 Instruction:0x428b CMP r3,r1

the analysis of divergences can omit differences in conditional instruction execution:

.. code-block:: bash

   $ paf-constanttime --image=check.elf \
        --ignore-conditional-execution-differences main check1.trace check2.trace
   index file check1.trace.index looks ok; not rebuilding it
   index file check2.trace.index looks ok; not rebuilding it
   Running analysis on trace 'check1.trace'
    - Building reference trace from main instance at time : 698 to 715
   698     X       CMP r0,#1
   699     -       BLE {pc}+0x1a
   700     X       LDR r1,[r1,#4]   R4(0x1a066)@0x106ffff8
   701     X       LDR r2,{pc}+0x1e         R4(0x1a164)@0x8050
   702     X       SUBS r3,r1,#1
   703     X       ADDS r1,#3
   704     X       LDRB r12,[r3,#1]!        R1(0x31)@0x1a066
   705     X       LDRB r0,[r2],#1  R1(0x31)@0x1a164
   706     X       CMP r12,r0
   707     -       BNE {pc}+0xa
   708     X       CMP r3,r1
   709     X       BNE {pc}-0xe
   710     X       LDRB r12,[r3,#1]!        R1(0x33)@0x1a067
   711     X       LDRB r0,[r2],#1  R1(0x32)@0x1a165
   712     X       CMP r12,r0
   713     X       BNE {pc}+0xa
   714     X       MOVS r0,#0
   715     X       BX lr
   Running analysis on trace 'check2.trace'
    - Comparing reference to instance at time : 698 to 721
      o Time:714 Executed:1 PC:0x804c ISet:1 Width:16 Instruction:0x2000 MOVS r0,#0 (reference)
        Time:714 Executed:1 PC:0x8044 ISet:1 Width:16 Instruction:0x428b CMP r3,r1

``paf-power``
~~~~~~~~~~~~~

``paf-power`` is a tool create a synthetic power trace for a function from a
set of tarmac traces. It's worth mentioning here that by nature synthetic
traces have no noise, which can confuse the tools to analyze them, so
``paf-power`` adds a small amount of noise by default (this can optionally be
turned off). ``paf-power`` will record one power trace per function execution
it found in the Tarmac traces.

The command line syntax looks like:
   ``paf-power`` [ *options* ] *FUNCTION* *TRACEFILE*\ ...

The following options are recognized:

``-o`` or ``--output=OutputFilename``
  Output file name (default: standard output)

``--timing=TimingFilename``
  Emit timing information to TimingFilename

``--csv``
  Emit the power trace in CSV format (default)

``--npy``
  Emit the power trace in NPY format

``--detailed-output``
  Emit more detailed information in the CSV file

``--no-noise``
  Do not add noise to the power trace

``--noise-level VALUE``
  Level of noise to add (default: 1.0)

``--uniform-noise``
  Use a uniform distribution noise sourceforge

``--normal-noise``
  Use a normal distribution noise source

``--hamming-weight``
  Use the hamming weight power model

``--hamming-distance``
  Use the hamming distance power model

``--image=IMAGEFILE``
  Image file name

``--only-index``
  Generate index and do nothing else

``--force-index``
  Regenerate index unconditionally

``--no-index``
  Do not regenerate index

``--li``
  Assume trace is from a little-endian platform

``--bi``
  Assume trace is from a big-endian platform

``-v`` or ``--verbose``
  Make tool more verbose

``-q`` or ``--quiet``
  Make tool quiet

``--show-progress-meter``
  force Display of the progress meter

For example, assume that you want to get a synthetic power trace, using the
Hamming weight model, of the execution of function ``gadget`` in
``program.elf``. You would first need to record a number of Tarmac traces using
run-model.py_ (with varying inputs to ``program.elf``), and then ``paf-power``
can build compute a synthetic power trace with:

.. code-block:: bash

   $ paf-power --hamming-weight --image=program.elf --npy -o traces.npy gadget traces/*.trace
   index file traces/program.0.trace.index looks ok; not rebuilding it
   index file traces/program.1.trace.index looks ok; not rebuilding it
   index file traces/program.2.trace.index looks ok; not rebuilding it
   ...
   Running analysis on trace 'traces/program.0.trace'
    - Building power trace from gadget instance at time : 594 to 606
   Running analysis on trace 'traces/program.1.trace'
    - Building power trace from gadget instance at time : 594 to 606
   Running analysis on trace 'traces/program.2.trace'
    - Building power trace from gadget instance at time : 594 to 606
   ...

``paf-correl``
~~~~~~~~~~~~~~

``paf-correl`` will compute the `Pearson correlation coefficient
<https://en.wikipedia.org/wiki/Pearson_correlation_coefficient>`_ for a trace
file considering some intermediate values.

The command line syntax looks like:
  ``paf-correl`` [ *options* ] *INDEX*\ ...

The following options are recognized:

``-v`` or ``--verbose``
  Increase verbosity level (can be specified multiple times)

``-a`` or ``--append``
  Append to output_file (instead of overwriting)

``-o FILE`` or ``--output=FILE``
  Write output to FILE (instead of stdout)

``-p`` or ``--python``
  Emit results in a format suitable for importing in python

``-g`` or ``--gnuplot``
  Emit results in gnuplot compatible format

``--numpy``
  Emit results in num^y format

``-f S`` or ``--from=S``
  Start computation at sample S (default: 0)

``-n N`` or ``--numsamples=N``
  Restrict computation to N samples

``-d T`` or ``--numtraces=T``
  Only process the first T traces

``-i INPUTSFILE`` or ``--inputs=INPUTSFILE``
  Use INPUTSFILE as input data, in npy format

``-t TRACESFILE`` or ``--traces=TRACESFILE``
  Use TRACESFILE as traces, in npy format

For example, to compute the Pearson correlation coefficient for the combination
``inputs[0] ^ inputs[1]`` for a number of traces in file ``traces.npy`` (with
50 samples per trace) that was generated assuming input values in file
``inputs.npy``:

.. code-block:: bash

   $ paf-correl -g -o data.gp -i inputs.npy -t traces.npy 0 1
   $ cat data.gp
   0  0.00300078
   1  -0.00619174
   2  0.0100264
   ...
   12  0.00902233
   13  -0.312871
   14  -0.325867
   15  -0.23732
   ...
   46  0.0185808
   47  0.00560168
   48  0.0162943
   49  0.0050634
   # max = -0.325867 at index 14

In this case, the correlation peak is found at sample 14, with a value of -0.325867.

``paf-ns-t-test``
~~~~~~~~~~~~~~~~~

``paf-ns-t-test`` is a utility to compute the non-specific t-test, i.e. it
computes the t-test between 2 groups of traces, without making any hypothesis
on an intermediate value.

The command line syntax looks like:
  ``paf-ns-t-test`` [ *options* ] *TRACES*\ ...

The following options are recognized:

``-v`` or ``--verbose``
  Increase verbosity level (can be specified multiple times)

``-a`` or ``--append``
  Append to output_file (instead of overwriting)

``-o FILE`` or ``--output=FILE``
  Write output to FILE (instead of stdout)

``-p`` or ``--python``
  Emit results in a format suitable for importing in python

``-g`` or ``--gnuplot``
  Emit results in gnuplot compatible format

``--numpy``
  Emit results in num^y format

``--perfect``
  assume perfect inputs (i.e. no noise).

``--decimate=PERIOD%OFFSET``
  decimate result (default: PERIOD=1, OFFSET=0)

``-f S`` or ``--from=S``
  Start computation at sample S (default: 0)

``-n N`` or ``--numsamples=N``
  Restrict computation to N samples

``--interleaved``
  Assume interleaved traces in a single NPY file

For example, let's assume that we have two groups of traces, recorded in two
separate files. The non-specific t-test, starting from sample 80, can be
computed with:

.. code-block:: bash

   $ paf-ns-t-test -g -o data.gp -v -f 80 group0.npy group1.npy
   Performing non-specific T-Test on traces : group0.npy group1.npy
   Saving output to 'data.gp'
   Read 25000 traces (100 samples) from 'group0.npy'
   Read 25000 traces (100 samples) from 'group1.npy'
   Will process 20 samples per traces, starting at sample 80

   $ cat data.gp
   0  3.62867
   1  4.23146
   2  3.96177
   3  3.68285
   4  3.23287
   ...
   12  -8.14007
   13  -622.498
   14  -633.387
   15  -613.356
   16  -529.575
   17  -558.535
   18  -572.168
   19  -560.1
   # max = -633.387 at index 14

``paf-t-test``
~~~~~~~~~~~~~~

``paf-t-test`` is a utility to compute the specific t-test, that is a t-test
with an hypothesis on an intermediate value. The intermediate value is computed
from one (or more) expressions that is (are) provided on the command line.

The command line syntax looks like:
   ``paf-t-test`` [ *options* ] *EXPRESSION*\ ...

The following options are recognized:

``-v`` or ``--verbose``
  Increase verbosity level (can be specified multiple times)

``-a`` or ``--append``
  Append to output_file (instead of overwriting)

``-o FILE`` or ``--output=FILE``
  Write output to FILE (instead of stdout)

``-p`` or ``--python``
  Emit results in a format suitable for importing in python

``-g`` or ``--gnuplot``
  Emit results in gnuplot compatible format

``--numpy``
  Emit results in num^y format

``--perfect``
  assume perfect inputs (i.e. no noise).

``--decimate=PERIOD%OFFSET``
  decimate result (default: PERIOD=1, OFFSET=0)

``-f S`` or ``--from=S``
  Start computation at sample S (default: 0)

``-n N`` or ``--numsamples=N``
  Restrict computation to N samples

``-t TRACESFILE`` or ``--traces=TRACESFILE``
  Use TRACESFILE as traces, in npy format

``-i INPUTSFILE`` or ``--inputs=INPUTSFILE``
  Use INPUTSFILE as input data, in npy format

``-m MASKSFILE`` or ``--masks=MASKSFILE``
  Use MASKSFILE as mask data, in npy format

``-k KEYSFILE`` or ``--keys=KEYSFILE``
  Use KEYSFILE as key data, in npy format

For example, to get the specific t-test for the intermediate 8-bit value ``inputs[0]
^ keys[0]`` for traces in ``traces.npy`` generated with data in
``inputs.npy`` and ``keys.npy``, for the 70 samples starting from sample 80:

.. code-block:: bash

   $ paf-t-test -g -o data.gp -v -f 80 -n 70 -i inputs.npy -k keys.npy -t traces.npy 'trunc8(xor($in[0],$key[0])'
   Reading traces from: 'traces.npy'
   Reading inputs from: 'inputs.npy'
   hw_max=32
   Input classification: HAMMING_WEIGHT
   Index: 0 1
   Saving output to 'data.gp'
   Read 20000 traces (150 samples per trace)
   Read 20000 inputs (8 data per trace)
   Will process 70 samples per traces, starting at sample 80
   $ cat data.gp
   0  -1.34559
   1  0.534966
   2  -0.694472
   3  -0.210325
   ...
   30  26.6723
   31  26.548
   32  24.1231
   33  63.1241
   34  60.8476
   35  57.8299
   36  47.5652
   37  34.4497
   38  30.407
   39  28.7012
   ...
   67  -14.8748
   68  -13.4678
   69  -11.1817
   # max = 63.1241 at index 33

*EXPRESSION*\ s are a strongly- and explicitely-typed mini-language supporting:

* Literals, that are expressed in decimal form and postfixed with ``_u8``, ``_u16``,
  ``_u32`` or ``_u64`` to express a literal value with respectively 8-, 16-,
  32- or 64-bit.

* Inputs, ``$in[idx]``, ``$key[idx]`` and ``$masks[idx]`` wich correspond to the ``idx``
  element of a row read respectively from ``INPUTSFILE``, ``KEYSFILE`` and ``MASKSFILE``.

* Unary operators: ``NOT(...)`` (bitwise not), ``TRUNC8(...)`` (truncation to 8-bit),
  ``TRUNC16(...)`` (truncation to 16-bit), ``TRUNC32(...)`` (truncation to 32-bit),
  ``AES_SBOX(...)`` (look-up value from the AES SBOX) and
  ``AES_ISBOX(...)`` (reverse look-up from the AES SBOX). The ``TRUNC*`` operators
  effectively convert the type of their inputs to 8-, 16-, 32-bit values. The ``AES_*``
  operators expect and return 8-bit values. ``NOT`` will return a value of the same
  type as its input.

* Binary operators: ``AND(..., ...)`` (bitwise and), ``OR(..., ...)`` (bitwise or),
  ``XOR(..., ...)`` (bitwise xor), ``LSL(..., ...)`` (logical shift left),
  ``LSR(..., ...)`` (logical shift right) and ``ASR(..., ...)`` (arithmetic shift right).
  Both operands of a binary operator must have the same type, and the operator result
  will have the same type as its inputs.

``paf-np-create``
~~~~~~~~~~~~~~~~~

``paf-np-create`` is a utility to create simple 1D or 2D numpy arrays. It's
used mostly for testing, but can be handy at times.

The command line syntax looks like:
  ``paf-np-create`` [ *options* ] *VALUE*\ ...

where ``VALUE`` is the values to use when filling the matrix.

The following options are recognized:

``-v`` or ``--verbose``
  Increase verbosity level (can be specified multiple times)

``-r ROWS`` or ``--rows=ROWS``
  Number of rows in the matrix

``-c COLUMNS`` or ``--columns=COLUMNS``
  Number of columns in the matrix

``-t ELT_TYPE`` or ``--element-type=ELT_TYPE``
  Select matrix element typei, where ``ELT_TYPE`` is one of numpy element types
  (e.g. ``u8``, ``i16``, ``f32``, ...)

``-o FILE`` or ``--output=FILE``
  Specify output file name

Example usage, to create a numpy file ``example.npy`` containing a 2 x 4 matrix
of ``double`` elements initialized with: 0.0 .. 7.0:

.. code-block:: bash

  $ paf-np-create -t f8 -r 2 -c 4 -o example.npy 0.0 1.0 2.0 3.0 4.0 5.0 6.0 7.0

``paf-np-utils``
~~~~~~~~~~~~~~~~

``paf-np-utils`` is a query utility to display information about a numpy file,
like number of rows or columns, ...

The command line syntax looks like:
  ``paf-np-utils`` [ *options* ] *NPY*

The following options are recognized:

``-v`` or ``--verbose``
  Increase verbosity level (can be specified multiple times)

``-r`` or ``--rows``
  Print number of rows

``-c`` or ``--columns``
  Print number of columns (this is the default action)

``-t`` or ``--elttype``
  Print element type

``-p`` or ``--python-content``
  Print array content as a python array

``-f`` or ``--c-content``
  Print array content as a C/C++ array

``-i`` or ``--info``
  Print NPY file information

``-m`` or ``--revision``
  Print NPY revision

Example usage, querying the element type in file ``example.npy``, as created in
the example for ``paf-np-create`` :

.. code-block:: bash

  $ paf-np-utils -t example.npy
  <f8

``paf-np-expand``
~~~~~~~~~~~~~~~~~

``paf-np-expand`` is a utility to expand or trunc a matrix, on the x and/or y axis with modulo.
It can optionnaly add noise to the samples in the matrix.

The command line syntax looks like:
  ``paf-np-expand`` [ *options* ] *NPY*

The following options are recognized:

``-v`` or ``--verbose``
  increase verbosity level (can be specified multiple times)

``-o`` or ``--output=FILENAME``
  NPY output file name (if not specified, input file will be overwritten)

``-c`` or ``--columns=NUM_COLS``
  Number of column to expand to. If not set, use all columns from the source NPY.

``-r`` or ``--rows=NUM_ROWS``
  Number of rows to expand to. If not set, use all rows from the source NPY.

``--noise=NOISE_LEVEL``
  Add noise to all samples (default: 0.0, i.e. no noise)

``--uniform-noise``
  Use a uniform distribution noise sourceforge

``--normal-noise``
  Use a normal distribution noise source

.. code-block:: bash

  $ paf-np-create -o source.npy -t f8 -r 2 -c 3 1.0 2.0 3.0 4.0 5.0 6.0
  $ paf-np-utils -p source.npy
  [
    [ 1, 2, 3 ],
    [ 4, 5, 6 ],
  ]
  $ paf-np-expand -o dest.npy -r 4 -c 2 --noise 0.5 source.npy
  $ paf-np-utils -p dest.npy
  [
    [ 1.42664, 2.21827 ],
    [ 4.08553, 5.38625 ],
    [ 1.09103, 2.39464 ],
    [ 4.29554, 5.0181 ],
  ]

Contributing to PAF
===================

Code contributions, in the form of comments, bug reports or patches, are most welcomed !

Please use the GitHub issue tracker associated with this repository for feedback.

Foreword on contributions
-------------------------

No coding style is perfect to everyone, and the code style used by PAF
does not claim to be perfect, we just aim to have it consistent, as it helps
working with the code base: developers' eyes are agile enough to quickly adapt
provided the formatting is consistent. But formatting is boring, no developper
should have to worry about it in the 21st century ! We have thus provided a
``.clang-format``, which allows to automate the formating consistantly in most
develoment environments. Please use it !

Code base organization
----------------------

PAF's general philosophy is to implement as much as possible in libraries, with
the application just being a specific glueing of the components in the
libraries. The bulk of PAF is C++ code, but a few parts, most notably
`run-model.py`_ are written in Python.

The code base organization reflects different domains tackled by PAF:

* fault injection related libraries (in ``include/PAF/FI`` and ``lib/FI``)

* side channel related libraries (in ``include/PAF/SCA`` and ``lib/SCA``)

* common libraries (in ``include/PAF`` and ``lib/PAF``)

and it also has mundane parts like :

* unit tests (in ``unit-test/``)

* end to end tests (in ``tests/``)

* continuous integration testing (in ``.github/workflows/``)

* documentation (in ``doc/``)

* build configuration (in ``cmake/``)

Build
-----

The configuration and build system used for PAF is `CMake <https://cmake.org/>`_.

Test
----

Unit tests
~~~~~~~~~~

Most unit tests are using the `GoogleTest
<https://github.com/google/googletest>`_ framework, but a few parts like those
written in Python have their dedicated unit tests. All unit tests have been
grouped together, using CMake_'s `CTest
<https://cmake.org/cmake/help/latest/module/CTest.html>`_.

Unit tests can be run with the ``test`` target. For example, if PAF's codebase
has been configured by ``cmake`` to use the ``ninja`` tool :

.. code-block:: bash

   $ ninja -C build/ test
   ninja: Entering directory `build/'
   [0/1] Running tests...
   Test project /Users/arndeg01/Software/CM-Security/PAF.git/build
         Start  1: unit-Intervals
    1/11 Test  #1: unit-Intervals ...................   Passed    0.02 sec
         Start  2: unit-Oracle
    2/11 Test  #2: unit-Oracle ......................   Passed    0.02 sec
         Start  3: nputils-python-tests
    3/11 Test  #3: nputils-python-tests .............   Passed    1.11 sec
         Start  4: npcreate-python-tests
    4/11 Test  #4: npcreate-python-tests ............   Passed    0.46 sec
         Start  5: unit-CPUInfo
    5/11 Test  #5: unit-CPUInfo .....................   Passed    0.02 sec
         Start  6: unit-Fault
    6/11 Test  #6: unit-Fault .......................   Passed    0.02 sec
         Start  7: unit-PAF
    7/11 Test  #7: unit-PAF .........................   Passed    0.02 sec
         Start  8: unit-Power
    8/11 Test  #8: unit-Power .......................   Passed    0.02 sec
         Start  9: unit-SCA
    9/11 Test  #9: unit-SCA .........................   Passed    0.06 sec
         Start 10: unit-NPArray
   10/11 Test #10: unit-NPArray .....................   Passed    0.02 sec
         Start 11: unit-Expr
   11/11 Test #11: unit-Expr ........................   Passed    0.02 sec
   
   100% tests passed, 0 tests failed out of 11
   
   Total Test time (real) =   1.83 sec

End to end tests
~~~~~~~~~~~~~~~~

The end-to-end testing tests together ``ruun-model.py`` and ``paf-faulter``; it
thus requires access to a FastModel. It is also intended for the time being to
be run manually, as the results depend on the cross-compiler used.

Continuous integration
~~~~~~~~~~~~~~~~~~~~~~

PAF's continuous integration relies on GitHub's Actions and workflows to build
and run unit testing on a number of platforms.

Documentation
-------------

The documentation is written in the `reStructuredText
<https://docutils.sourceforge.io/rst.html>`_ format. It allows easy written,
and can be transformated automatically to html and pdf, and is rendered
directly by GitHub.

When modifying the documentation, please check that it's still parsed
correctly, by using ``rst2html5.py`` for example:

.. code-block:: bash

   $ rst2html5.py doc/index.rst build/doc/index.html
