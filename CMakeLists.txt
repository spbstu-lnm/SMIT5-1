# CMakeList.txt: проект CMake для SMIT5-1; включите исходный код и определения,
# укажите здесь логику для конкретного проекта.
#
cmake_minimum_required (VERSION 3.20)	# 3.20 required for C++23

# Включение горячей перезагрузки для компиляторов MSVC, если поддерживается.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("SMIT5-1")


# added for the whole project
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX WIN32_NO_STATUS)


# Добавьте источник в исполняемый файл этого проекта.
add_executable (SMIT5-1 "SMIT5-1.cpp" "SMIT5-1.h" "SMIT5-1Shared.h")
