# how to use this

1. Download `llvm-13.0.0` project source code.
2. Copy the folder into `lib/Transforms/` folder of your `llvm-13.0.0.src` folder.
3. Edit the original `CMakeLists.txt` file to include the new `CallAndDerefPass` folder.
4. Compile the llvm in **release** mode (refer to their documentation on this).
