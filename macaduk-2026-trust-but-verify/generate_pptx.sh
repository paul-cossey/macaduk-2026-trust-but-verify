#!/bin/bash

# Powerpoint path:
powerpoint_path="/Applications/Microsoft PowerPoint.app"

# Check if PowerPoint is installed at the specified path.
if ! [ -d "${powerpoint_path}" ];
then
    # Print an error message to the console
    /bin/echo "Microsoft PowerPoint is not installed at ${powerpoint_path}. Please install it and try again."
    # Exit with a non-zero status code to indicate an error.
    exit 1
fi

# Print a message to the console indicating that we're deactivating the virtual environment
/bin/echo "Terminating Microsoft PowerPoint, if it's running..."

# Quit PowerPoint, if it's running...
/usr/bin/killall "Microsoft PowerPoint"

# Get the path to this scripts parent directory.
script_dir=$(dirname "$(readlink -f "$0")")

# Print the script directory to the console.
/bin/echo "Script directory: ${script_dir}..."

# Change to the script directory.
cd "${script_dir}" || exit

# Print the script directory to the console.
/bin/echo "cd'd into the script directory: ${PWD}..."

# Set the PYTHONPATH to the script directory so that the create_pptx.py script can import the utils module.
export PYTHONPATH="${script_dir}"

# Print the PYTHONPATH to the console.
/bin/echo "PYTHONPATH set to: ${PYTHONPATH}..."

# Create a virtual environment in the script directory.
python3 -m venv "${script_dir}/venv"

# Print a message to the console indicating that the virtual environment has been created.
/bin/echo "Created the virtual environment at: ${script_dir}/venv..."

# Activate the virtual environment.
source "${script_dir}/venv/bin/activate"

# Print a message to the console indicating that the virtual environment has been activated.
/bin/echo "Activated the virtual environment..."

# Print a message that we're installing the required packages from the requirements.txt file.
/bin/echo "Installing the required packages from the requirements.txt file..."

# Install the required packages from the requirements.txt file.
pip install -r "${script_dir}/requirements.txt"

# Print a message to the console indicating that the required packages have been installed.
/bin/echo "Installed the required packages from the requirements.txt file..."

# Set the library path for cairo (installed via Homebrew).
export DYLD_LIBRARY_PATH="/opt/homebrew/lib:${DYLD_LIBRARY_PATH}"

# Generate the spy duck animated GIF if cairosvg is available.
/bin/echo "Generating the spy duck animated GIF..."
python "${script_dir}/generate_spy_duck_gif.py" || /bin/echo "Warning: Could not generate spy duck GIF (cairo may not be installed)."

# Print a message to the console indicating that we're running the create_pptx.py script.
/bin/echo "Running the create_pptx.py script..."

# Run the create_pptx.py script.
python "${script_dir}/create_pptx.py"

# Print a message to the console indicating that the create_pptx.py script has finished running.
/bin/echo "Finished running the create_pptx.py script..."

# Print a message to the console indicating that we're opening the pptx in PowerPoint.
/bin/echo "Opening the pptx in Microsoft PowerPoint..."

# Open the pptx in PowerPoint...
/usr/bin/open -a "/Applications/Microsoft PowerPoint.app" "${script_dir}/Trust_But_Verify_MacAD_UK_2026.pptx"