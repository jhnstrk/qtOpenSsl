project(test)

include_directories("../src")

set( ${PROJECT_NAME}_HEADERS_MOC 
    test_aes.h
    )

set( ${PROJECT_NAME}_HEADERS
  ${${PROJECT_NAME}_HEADERS_MOC}
  )

set( ${PROJECT_NAME}_MAIN_SOURCES
    test_aes.cpp
    )

set( ${PROJECT_NAME}_SOURCES 
  ${${PROJECT_NAME}_MAIN_SOURCES}
  )

#create_test_sourcelist(${PROJECT_NAME}_SOURCES_TEST ${PROJECT_NAME}.cxx
#  ${${PROJECT_NAME}_MAIN_SOURCES})

#foreach(test ${${PROJECT_NAME}_MAIN_SOURCES})
#  get_filename_component(TName ${test} NAME_WE)
#  add_test(NAME ${TName} COMMAND $<TARGET_FILE:${PROJECT_NAME}> ${TName})
#endforeach()

qt5_wrap_cpp(${PROJECT_NAME}_SOURCES_MOC ${${PROJECT_NAME}_HEADERS_MOC})

add_executable(${PROJECT_NAME}
  ${${PROJECT_NAME}_SOURCES}
  ${${PROJECT_NAME}_SOURCES_MOC}
  ${${PROJECT_NAME}_HEADERS}
  )

target_link_libraries(${PROJECT_NAME} qtCrypto)

qt5_use_modules(${PROJECT_NAME} Test)   #testlib?

add_custom_target(RunTests
                  COMMAND ${PROJECT_NAME}
                  DEPENDS ${PROJECT_NAME}
                  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
                  COMMENT "Run tests" # [VERBATIM]
                  #SOURCES source1...
                  )
