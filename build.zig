// Build libsintykey (Zig, C-ABI preserved). Zig 0.16.
// PIC so it links into PIE consumers (the GTK installer/shell). Ships both a
// static (.a) and a shared (.so) library plus the C header.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Security-relevant settings are COMPILE-TIME, never runtime env vars: a binary
    // that runs inside PAM must not let a caller redirect the state dir / TPM helper
    // or disable encryption via the environment. The shipped image builds with the
    // secure defaults; only test builds override.
    const opts = b.addOptions();
    opts.addOption([]const u8, "state_dir", b.option([]const u8, "state-dir", "key/blob state directory") orelse "/var/lib/sinty");
    // DEDICATED root-only (0700) tmpfs dir -- NOT /run/sinty, which is the 1777 world-writable
    // multi-user session registry (a world-writable scratch would let a local user pre-create our
    // predictable secret files and read the unsealed CE key). Transient plaintext (PIN, raw CE/
    // device key, unseal output) goes here so cleartext never hits the unencrypted persistent disk.
    opts.addOption([]const u8, "scratch_dir", b.option([]const u8, "scratch-dir", "dedicated root-only tmpfs scratch for transient plaintext secrets") orelse "/run/sintykey");
    opts.addOption([]const u8, "tpm_bin", b.option([]const u8, "tpm-bin", "path to sintykey-tpm") orelse "/usr/libexec/sintykey-tpm");
    opts.addOption(bool, "enforce_fscrypt", b.option(bool, "enforce-fscrypt", "provision MUST set an fscrypt policy (no skip)") orelse true);
    // provision MUST seal to a working TPM: otherwise it would silently create an
    // account whose PIN cannot unseal (login dead, only recovery works) yet report
    // success. Dev builds may disable to exercise the recovery-wrap path.
    opts.addOption(bool, "enforce_tpm", b.option(bool, "enforce-tpm", "provision MUST succeed the TPM seal") orelse true);
    // E2E-only: logs fscrypt key identifiers + key hashes to /var/lib/sinty/.dbg-*
    // for debugging fscrypt key issues across reboots. NEVER set in a release image.
    opts.addOption(bool, "debug_e2e", b.option(bool, "debug-e2e", "E2E diagnostics to .dbg-* files") orelse false);
    const opts_mod = opts.createModule();

    const mod = b.createModule(.{
        .root_source_file = b.path("libsintykey/libsintykey.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
    });

    const static = b.addLibrary(.{ .name = "sintykey", .linkage = .static, .root_module = mod });
    static.installHeader(b.path("libsintykey/libsintykey.h"), "libsintykey.h");
    b.installArtifact(static);

    const shared = b.addLibrary(.{ .name = "sintykey", .linkage = .dynamic, .root_module = mod });
    b.installArtifact(shared);

    // pam_sinty.so: the PAM module. Links libsintykey + libpam.
    const pam = b.addLibrary(.{
        .name = "pam_sinty",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("pam_sinty/pam_sinty.zig"),
            .target = target,
            .optimize = optimize,
            .pic = true,
            .link_libc = true,
            .imports = &.{.{ .name = "build_options", .module = opts_mod }},
        }),
    });
    // pam_sinty execs the sintykey CLI for the TPM unseal (one key-custody path),
    // so it links only libpam -- no libsintykey dependency.
    pam.root_module.linkSystemLibrary("pam", .{});
    b.installArtifact(pam);

    // sintykey CLI: provision / change-pin / verify-pin (the single helper).
    const cli = b.addExecutable(.{
        .name = "sintykey",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cmd/sintykey/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sintykey", .module = mod },
                .{ .name = "build_options", .module = opts_mod },
            },
        }),
    });
    b.installArtifact(cli);

    // sintykey-tpm: the native TPM 2.0 backend over libtss2 ESYS. Replaces the shell
    // wrapper -- no tpm2-tools subprocess and no PATH lookup in a root-run seal/verify path.
    const tpm_be = b.addExecutable(.{
        .name = "sintykey-tpm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tpm/sintykey-tpm.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    tpm_be.root_module.linkSystemLibrary("tss2-esys", .{});
    tpm_be.root_module.linkSystemLibrary("tss2-mu", .{});
    tpm_be.root_module.linkSystemLibrary("tss2-rc", .{});
    tpm_be.root_module.linkSystemLibrary("tss2-tctildr", .{});
    b.installArtifact(tpm_be);

    const t = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("libsintykey/libsintykey.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    b.step("test", "run tests").dependOn(&b.addRunArtifact(t).step);
}
