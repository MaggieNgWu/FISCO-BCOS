function(eth_apply TARGET REQUIRED)
if (USE_HSM_SDF)
	set(OPENSSL_INCLUDE_DIRS ${SWSSL_INCLUDE_DIRS})
	target_include_directories(${TARGET} SYSTEM PUBLIC ${SWSSL_INCLUDE_DIRS})
	target_link_libraries(${TARGET} PUBLIC ${SWSSL_LIBRARIES})
	set_property(TARGET ${TARGET} PROPERTY INTERFACE_LINK_LIBRARIES ${SWSSL_LIBRARIES})
else()
	set(OPENSSL_INCLUDE_DIRS ${TASSL_INCLUDE_DIRS})
	target_include_directories(${TARGET} SYSTEM PUBLIC ${TASSL_INCLUDE_DIRS})
	target_link_libraries(${TARGET} PUBLIC ${TASSL_LIBRARIES})
	set_property(TARGET ${TARGET} PROPERTY INTERFACE_LINK_LIBRARIES ${TASSL_LIBRARIES})
endif()
endfunction()
