clion_conan_r:
	rm -rf cmake-build-release
	mkdir cmake-build-release
	cd cmake-build-relese && conan install .. -s build_type=Release -s compiler.cppstd=17 --output-folder=. --build missing

clion_conan_d:
	rm -rf cmake-build-debug
	mkdir cmake-build-debug
	cd cmake-build-debug && conan install .. -s build_type=Debug -s compiler.cppstd=17 --output-folder=. --build missing


vscode_conan_d:
	rm -rf build
	mkdir cbuild
	cd cmake-build-relese && conan install .. -s build_type=Release -s compiler.cppstd=17 --output-folder=. --build missing

vscode_conan_r:
	rm -rf build
	mkdir build
	cd build && conan install .. -s build_type=Debug -s compiler.cppstd=17 --output-folder=. --build missing
