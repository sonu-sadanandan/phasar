# Define C/C++ Test Sources for Cluster Taint Analysis
set(JsonConfig_ClusterTestSources
  test01_source_to_sink.c
  test02_sanitizer_blocks.c
  test03_branchy_propagation.c
  test04_interproc.c
  test05_pointer_alias.c
  test06_partial_sanitize.c
  test07_overwrite_kills.c
  test08_cpp_string.cpp
  test09_clusterExample.cpp
  test10_sample.cpp
  return_src.c
  outparam_src.c
  libc_fgets_cmd.c
)

foreach(TEST_SRC ${JsonConfig_ClusterTestSources})
  generate_ll_file(FILE ${TEST_SRC} DEBUG)
endforeach(TEST_SRC)


# Define JSON Configuration Files for Cluster Tests
set(JsonConfig_ClusterConfigFiles
  cluster_Example_config.json
  sample_config.json
  taint_config_basic.json
  taint_config_libc.json
  return_taint.json
  libc_cmd.json
  outparam_taint.json
)

# Copy each JSON configuration file from the source directory to the build directory.
foreach(TEST_CONFIG ${JsonConfig_ClusterConfigFiles})
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/${TEST_CONFIG}
    ${CMAKE_CURRENT_BINARY_DIR}
    COPYONLY
  )
endforeach(TEST_CONFIG)