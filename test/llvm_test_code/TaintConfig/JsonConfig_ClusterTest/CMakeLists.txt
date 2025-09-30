# Define C/C++ Test Sources for Cluster Taint Analysis
# Replace the placeholder names with your actual .c or .cpp files.
set(JsonConfig_ClusterTestSources
  clusterExample.cpp
  testsample.cpp
)

# Compile each source file into its LLVM intermediate representation (.ll file).
# This uses the 'generate_ll_file' function defined elsewhere in your project.
foreach(TEST_SRC ${JsonConfig_ClusterTestSources})
  generate_ll_file(FILE ${TEST_SRC} DEBUG)
endforeach(TEST_SRC)


# Define JSON Configuration Files for Cluster Tests
# Replace the placeholder names with your actual .json configuration files.
set(JsonConfig_ClusterConfigFiles
  clusterExample_config.json
  testsample_config.json
)

# Copy each JSON configuration file from the source directory to the build directory.
# This uses the 'configure_file( ... COPYONLY)' approach.
foreach(TEST_CONFIG ${JsonConfig_ClusterConfigFiles})
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_CONFIG}
    ${CMAKE_CURRENT_BINARY_DIR}
    COPYONLY
  )
endforeach(TEST_CONFIG)