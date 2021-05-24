function(eth_apply TARGET REQUIRED)
	set(OPENSSL_INCLUDE_DIRS ${SWSSL_INCLUDE_DIRS})
	target_include_directories(${TARGET} SYSTEM PUBLIC ${SWSSL_INCLUDE_DIRS})
	target_link_libraries(${TARGET} PUBLIC ${SWSSL_LIBRARIES})
	set_property(TARGET ${TARGET} PROPERTY INTERFACE_LINK_LIBRARIES ${SWSSL_LIBRARIES})
endfunction()
