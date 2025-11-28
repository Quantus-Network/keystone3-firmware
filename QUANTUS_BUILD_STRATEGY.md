# Quantus Build Strategy

This document outlines the plan to integrate the Quantus coin into the Keystone3 firmware using a dedicated build variant, similar to the "Cypherpunk" edition. This approach ensures isolation of Quantus-specific features from the main "Web3" and "BTC-Only" codebases, which is beneficial for auditing and maintenance.

## 1. Build System Modifications

### `build.py`
We need to add a new build type argument (e.g., `quantus`) to the build script to trigger the specific build configuration.

-   Update `build.py` to accept `quantus` as a `type` argument.
-   Set a flag (e.g., `is_quantus`) based on this argument.
-   Pass a definition `-DQUANTUS=true` to the CMake command when this flag is set.

### `CMakeLists.txt`
We need to handle the new `QUANTUS` definition in CMake to define the compilation macro and set the correct source paths.

-   Add a conditional block `if(QUANTUS)`:
    -   Define `QUANTUS_VERSION` globally using `add_compile_definitions`.
    -   Set `WIDGET_SUBPATH` to `multi/quantus`.
    -   Set `BUILD_VARIANT` to `QUANTUS`.
-   Ensure this block is mutually exclusive with `CYPHERPUNK`, `BTC_ONLY`, and the default `WEB3_VERSION`.

## 2. Source Code Isolation

### Directory Structure
Create a new directory for Quantus-specific UI widgets to keep them separate from `web3` and `cypherpunk` widgets.

-   **New Directory:** `src/ui/gui_widgets/multi/quantus/`
-   **Files to Create:**
    -   `gui_quantus_home_widgets.h`: Defines macros like `HOME_WALLET_CARD_SURPLUS` specific to Quantus.
    -   `gui_quantus_home_widgets.c`: Implements the home screen logic for the Quantus build.
    -   `gui_connect_wallet_widgets.c`: Implements the wallet connection list specific to Quantus.

### Conditional Compilation (`#ifdef`)
Use the `QUANTUS_VERSION` macro to isolate Quantus code in shared files.

-   **`src/ui/gui_chain/gui_chain.h`**:
    -   Add `CHAIN_QUANTUS` inside an `#ifdef QUANTUS_VERSION` block (or shared if appropriate, but isolated from Web3 if desired).
-   **`src/ui/gui_components/gui_status_bar.c`**:
    -   Define `g_coinWalletBtn` entries for Quantus inside `#ifdef QUANTUS_VERSION`.
-   **`src/ui/gui_widgets/multi/gui_home_widgets.h`**:
    -   Include `quantus/gui_quantus_home_widgets.h` when `QUANTUS_VERSION` is defined.

## 3. Implementation Steps

1.  **Modify `build.py`**: Add the `quantus` type support.
2.  **Modify `CMakeLists.txt`**: Add the `QUANTUS` logic.
3.  **Create Directory**: `mkdir -p src/ui/gui_widgets/multi/quantus`.
4.  **Create Widget Files**:
    -   Copy `gui_cypherpunk_home_widgets.h/.c` as templates for `gui_quantus_home_widgets.h/.c`.
    -   Modify them to reference Quantus coins instead of Zcash/Monero.
5.  **Update Shared Headers**: Add `#ifdef QUANTUS_VERSION` blocks in `gui_chain.h` and others where the coin enum is defined.
6.  **Build**: Run `python3 build.py -t quantus` to generate the firmware.

## 4. Benefits

-   **Clean Separation**: Quantus code does not clutter the main Web3 build.
-   **Auditability**: It is clear exactly what code is active for the Quantus build.
-   ** maintainability**: Changes to Web3 or BTC builds are less likely to break the Quantus build, and vice versa.

