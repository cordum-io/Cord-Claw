class CordclawDaemon < Formula
  desc "Pre-dispatch governance daemon for OpenClaw"
  homepage "https://github.com/cordum-io/cordclaw"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/cordum-io/cordclaw/releases/download/v#{version}/cordclaw-daemon-darwin-arm64"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    else
      url "https://github.com/cordum-io/cordclaw/releases/download/v#{version}/cordclaw-daemon-darwin-amd64"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/cordum-io/cordclaw/releases/download/v#{version}/cordclaw-daemon-linux-arm64"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    else
      url "https://github.com/cordum-io/cordclaw/releases/download/v#{version}/cordclaw-daemon-linux-amd64"
      sha256 "REPLACE_WITH_LINUX_AMD64_SHA256"
    end
  end

  def install
    bin.install "cordclaw-daemon"
  end

  test do
    assert_match "cordclaw-daemon", shell_output("#{bin}/cordclaw-daemon --help")
  end
end
