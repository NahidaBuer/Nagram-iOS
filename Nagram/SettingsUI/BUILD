load("@build_bazel_rules_swift//swift:swift.bzl", "swift_library")
load("@build_bazel_rules_apple//apple:ios.bzl", "ios_unit_test")
load("@build_bazel_rules_apple//apple/testing/default_runner:ios_test_runner.bzl", "ios_test_runner")

# MARK: NAGRAM — Nagram 增强设置页 UI 层（ItemListController toggle）。
# 依赖数据层 Nagram/Settings + 上游 UI 模块；rebase 时上游碰不到 Nagram/。
swift_library(
    name = "NagramSettingsUI",
    module_name = "NagramSettingsUI",
    srcs = glob([
        "**/*.swift",
    ], exclude = [
        "Tests/**/*.swift",
    ]),
    copts = [
        "-warnings-as-errors",
    ],
    deps = [
        "//submodules/AccountUtils:AccountUtils",
        "//submodules/MtProtoKit:MtProtoKit",
        "//submodules/Display:Display",
        "//submodules/SSignalKit/SwiftSignalKit:SwiftSignalKit",
        "//submodules/TelegramPresentationData:TelegramPresentationData",
        "//submodules/ItemListUI:ItemListUI",
        "//submodules/PresentationDataUtils:PresentationDataUtils",
        "//submodules/AccountContext:AccountContext",
        "//submodules/TelegramCore:TelegramCore",
        "//submodules/TelegramUIPreferences:TelegramUIPreferences",
        "//submodules/UndoUI:UndoUI",
        "//Nagram/Settings:NagramSettings",
        "//Nagram/LinkMetadata:NagramLinkMetadata",
        "//Nagram/Strings:NagramStrings",
        "//Nagram/SettingsSignal:NagramSettingsSignal",
        # MARK: NAGRAM — 贴纸尺寸滑杆(SliderComponent,复刻省电模式粗轨道)
        "//submodules/AsyncDisplayKit",
        "//submodules/ComponentFlow",
        "//submodules/TelegramUI/Components/FaceScanScreen",
        "//submodules/TelegramUI/Components/SliderComponent",
        "//submodules/TelegramUI/Components/TabBarComponent",
        "//submodules/sqlcipher:sqlcipher",
    ],
    visibility = [
        "//visibility:public",
    ],
)

swift_library(
    name = "NagramSessionRecoveryTestsLib",
    testonly = True,
    srcs = glob([
        "Tests/**/*.swift",
    ]),
    deps = [
        ":NagramSettingsUI",
        ":NagramSessionRecoveryTestFrameworks",
        "//submodules/TelegramCore:TelegramCore",
        "//submodules/sqlcipher:sqlcipher",
    ],
)

objc_library(
    name = "NagramSessionRecoveryTestFrameworks",
    testonly = True,
    sdk_frameworks = [
        "MediaPlayer",
    ],
)

ios_test_runner(
    name = "NagramSessionRecoveryTestRunner",
    device_type = "iPhone 17",
    os_version = "26.5",
)

ios_unit_test(
    name = "NagramSessionRecoveryTests",
    minimum_os_version = "15.0",
    runner = ":NagramSessionRecoveryTestRunner",
    deps = [
        ":NagramSessionRecoveryTestsLib",
    ],
    visibility = [
        "//visibility:public",
    ],
)
