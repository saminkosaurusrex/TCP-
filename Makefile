BUILD_DIR=ipk-l4-scan

build:
	cd $(BUILD_DIR) && dotnet build
	cd $(BUILD_DIR) && dotnet publish -c Release -r linux-x64 --self-contained false -o .
#	cd $(BUILD_DIR) && dotnet publish -c Release -r osx-arm64 --self-contained false -o publish/mac-arm

run:
	cd $(BUILD_DIR) && dotnet run

clean:
	rm -rf $(BUILD_DIR)/bin $(BUILD_DIR)/obj $(BUILD_DIR)/*.json $(BUILD_DIR)/*.dll $(BUILD_DIR)/*.pdb 

all: build
