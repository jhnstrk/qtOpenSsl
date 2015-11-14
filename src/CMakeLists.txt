project( qtCrypto )

include_directories(${OPENSSL_INCLUDE_DIR})

add_library( qtCrypto SHARED 
  qcryptostream.h
  qcryptostream.cpp
  )

target_link_libraries( qtCrypto ${OPENSSL_LIBRARIES} )

qt5_use_modules(qtCrypto Core)

install(TARGETS qtCrypto
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
