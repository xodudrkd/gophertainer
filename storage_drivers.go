package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// StorageDriver represents a pluggable storage backend
type StorageDriver interface {
	// Name returns the driver name
	Name() string
	
	// Init initializes the storage driver
	Init(ctx context.Context, config StorageDriverConfig) error
	
	// Create creates a new container storage layer
	Create(ctx context.Context, id string, parentID string, opts CreateOptions) (*StorageInfo, error)
	
	// Mount mounts the container storage and returns the mount path
	Mount(ctx context.Context, id string, opts MountOptions) (string, error)
	
	// Unmount unmounts the container storage
	Unmount(ctx context.Context, id string) error
	
	// Remove removes the container storage layer
	Remove(ctx context.Context, id string) error
	
	// Exists checks if a storage layer exists
	Exists(ctx context.Context, id string) (bool, error)
	
	// Status returns driver status and statistics
	Status(ctx context.Context) (*StorageStatus, error)
	
	// Cleanup performs driver cleanup
	Cleanup(ctx context.Context) error
}

// StorageDriverConfig holds configuration for storage drivers
type StorageDriverConfig struct {
	Driver     string            `json:"driver"`      // Driver name (overlayfs, devicemapper)
	Options    map[string]string `json:"options"`     // Driver-specific options
	RootDir    string            `json:"root_dir"`    // Root directory for storage
	RunRoot    string            `json:"run_root"`    // Runtime directory
	GraphRoot  string            `json:"graph_root"`  // Graph root directory
}

// CreateOptions provides options for creating storage layers
type CreateOptions struct {
	MountLabel  string            `json:"mount_label"`
	StorageOpt  map[string]string `json:"storage_opt"`
	ReadWrite   bool              `json:"read_write"`
}

// MountOptions provides options for mounting storage
type MountOptions struct {
	MountLabel string   `json:"mount_label"`
	Options    []string `json:"options"`
	ReadWrite  bool     `json:"read_write"`
}

// StorageInfo contains information about a storage layer
type StorageInfo struct {
	ID         string            `json:"id"`
	ParentID   string            `json:"parent_id"`
	MountPath  string            `json:"mount_path"`
	Size       int64             `json:"size"`
	Metadata   map[string]string `json:"metadata"`
	Created    time.Time         `json:"created"`
	Driver     string            `json:"driver"`
}

// StorageStatus provides driver status information
type StorageStatus struct {
	Driver         string            `json:"driver"`
	RootDir        string            `json:"root_dir"`
	BackingFs      string            `json:"backing_fs"`
	SupportsDType  bool              `json:"supports_dtype"`
	Status         map[string]string `json:"status"`
	ConfigFile     string            `json:"config_file"`
}

// StorageManager manages storage drivers
type StorageManager struct {
	drivers map[string]StorageDriver
	config  StorageDriverConfig
	logger  *slog.Logger
}

// NewStorageManager creates a new storage manager
func NewStorageManager(ctx context.Context, config StorageDriverConfig) (*StorageManager, error) {
	logger := Logger(ctx).With("component", "storage-manager")
	
	sm := &StorageManager{
		drivers: make(map[string]StorageDriver),
		config:  config,
		logger:  logger,
	}
	
	// Register built-in drivers
	sm.RegisterDriver(&OverlayFSDriver{})
	sm.RegisterDriver(&DeviceMapperDriver{})
	
	// Initialize the configured driver
	if config.Driver != "" {
		driver, exists := sm.drivers[config.Driver]
		if !exists {
			return nil, WrapStorageError("driver_lookup", config.Driver, fmt.Errorf("unknown storage driver: %s", config.Driver))
		}
		
		if err := driver.Init(ctx, config); err != nil {
			return nil, WrapStorageError("driver_init", config.Driver, fmt.Errorf("failed to initialize %s driver: %w", config.Driver, err))
		}
		
		logger.Info("Storage driver initialized", "driver", config.Driver)
	}
	
	return sm, nil
}

// RegisterDriver registers a new storage driver
func (sm *StorageManager) RegisterDriver(driver StorageDriver) {
	sm.drivers[driver.Name()] = driver
}

// GetDriver returns the configured driver
func (sm *StorageManager) GetDriver() (StorageDriver, error) {
	driver, exists := sm.drivers[sm.config.Driver]
	if !exists {
		return nil, WrapStorageError("driver_get", sm.config.Driver, fmt.Errorf("driver %s not found", sm.config.Driver))
	}
	return driver, nil
}

// ListDrivers returns available driver names
func (sm *StorageManager) ListDrivers() []string {
	var drivers []string
	for name := range sm.drivers {
		drivers = append(drivers, name)
	}
	return drivers
}

// OverlayFSDriver implements storage driver for OverlayFS
type OverlayFSDriver struct {
	config    StorageDriverConfig
	logger    *slog.Logger
	lowerDir  string
	upperDir  string
	workDir   string
	mergedDir string
}

// Name returns the driver name
func (d *OverlayFSDriver) Name() string {
	return "overlayfs"
}

// Init initializes the OverlayFS driver
func (d *OverlayFSDriver) Init(ctx context.Context, config StorageDriverConfig) error {
	d.config = config
	d.logger = Logger(ctx).With("driver", "overlayfs")
	
	// Set up directory structure
	d.lowerDir = filepath.Join(config.GraphRoot, "overlay-layers", "lower")
	d.upperDir = filepath.Join(config.GraphRoot, "overlay-layers", "upper")
	d.workDir = filepath.Join(config.GraphRoot, "overlay-layers", "work")
	d.mergedDir = filepath.Join(config.GraphRoot, "overlay-layers", "merged")
	
	// Create directories
	for _, dir := range []string{d.lowerDir, d.upperDir, d.workDir, d.mergedDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return WrapStorageError("directory_create", dir, fmt.Errorf("failed to create directory %s: %w", dir, err))
		}
	}
	
	// Check for OverlayFS support
	if err := d.checkOverlaySupport(ctx); err != nil {
		return WrapStorageError("overlayfs_check", "/proc/filesystems", fmt.Errorf("overlayfs not supported: %w", err))
	}
	
	d.logger.Info("OverlayFS driver initialized", "root", config.GraphRoot)
	return nil
}

// checkOverlaySupport verifies OverlayFS support
func (d *OverlayFSDriver) checkOverlaySupport(ctx context.Context) error {
	// Check if overlay module is loaded
	if _, err := os.Stat("/proc/filesystems"); err == nil {
		data, err := os.ReadFile("/proc/filesystems")
		if err == nil && strings.Contains(string(data), "overlay") {
			return nil
		}
	}
	
	// Try to load overlay module
	if err := exec.CommandContext(ctx, "modprobe", "overlay").Run(); err != nil {
		return WrapStorageError("module_load", "overlay", fmt.Errorf("failed to load overlay module: %w", err))
	}
	
	return nil
}

// Create creates a new overlay layer
func (d *OverlayFSDriver) Create(ctx context.Context, id string, parentID string, opts CreateOptions) (*StorageInfo, error) {
	layerDir := filepath.Join(d.upperDir, id)
	if err := os.MkdirAll(layerDir, 0755); err != nil {
		return nil, WrapStorageError("layer_create", layerDir, fmt.Errorf("failed to create layer directory: %w", err))
	}
	
	// Create work directory for this layer
	workDir := filepath.Join(d.workDir, id)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, WrapStorageError("work_dir_create", workDir, fmt.Errorf("failed to create work directory: %w", err))
	}
	
	info := &StorageInfo{
		ID:        id,
		ParentID:  parentID,
		Size:      0,
		Metadata:  make(map[string]string),
		Created:   time.Now(),
		Driver:    d.Name(),
	}
	
	// Save layer metadata
	if err := d.saveLayerInfo(id, info); err != nil {
		return nil, WrapStorageError("layer_info_save", id, fmt.Errorf("failed to save layer info: %w", err))
	}
	
	d.logger.Info("Created overlay layer", "id", id, "parent", parentID)
	return info, nil
}

// Mount mounts the overlay filesystem
func (d *OverlayFSDriver) Mount(ctx context.Context, id string, opts MountOptions) (string, error) {
	mergedDir := filepath.Join(d.mergedDir, id)
	if err := os.MkdirAll(mergedDir, 0755); err != nil {
		return "", WrapStorageError("merged_dir_create", mergedDir, fmt.Errorf("failed to create merged directory: %w", err))
	}
	
	upperDir := filepath.Join(d.upperDir, id)
	workDir := filepath.Join(d.workDir, id)
	
	// Build overlay mount options
	var lowerDirs []string
	
	// Get layer info to find parent layers
	info, err := d.getLayerInfo(id)
	if err != nil {
		return "", WrapStorageError("layer_info_get", id, fmt.Errorf("failed to get layer info: %w", err))
	}
	
	// Build lower layer chain
	if info.ParentID != "" {
		parentLowers, err := d.getLowerDirs(info.ParentID)
		if err != nil {
			return "", WrapStorageError("parent_lower_dirs", info.ParentID, fmt.Errorf("failed to get parent lower dirs: %w", err))
		}
		lowerDirs = append(lowerDirs, parentLowers...)
	}
	
	// Add base layer if exists
	baseLayer := filepath.Join(d.lowerDir, "base")
	if _, err := os.Stat(baseLayer); err == nil {
		lowerDirs = append(lowerDirs, baseLayer)
	}
	
	// Construct mount options
	mountOpts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s",
		strings.Join(lowerDirs, ":"), upperDir, workDir)
	
	// Mount overlay
	if err := unix.Mount("overlay", mergedDir, "overlay", 0, mountOpts); err != nil {
		return "", WrapStorageError("overlay_mount", mergedDir, fmt.Errorf("failed to mount overlay: %w", err))
	}
	
	d.logger.Info("Mounted overlay", "id", id, "path", mergedDir)
	return mergedDir, nil
}

// Unmount unmounts the overlay filesystem
func (d *OverlayFSDriver) Unmount(ctx context.Context, id string) error {
	mergedDir := filepath.Join(d.mergedDir, id)
	
	if err := unix.Unmount(mergedDir, 0); err != nil && !os.IsNotExist(err) {
		return WrapStorageError("overlay_unmount", mergedDir, fmt.Errorf("failed to unmount overlay: %w", err))
	}
	
	d.logger.Info("Unmounted overlay", "id", id)
	return nil
}

// Remove removes an overlay layer
func (d *OverlayFSDriver) Remove(ctx context.Context, id string) error {
	// Unmount first
	if err := d.Unmount(ctx, id); err != nil {
		d.logger.Warn("Failed to unmount before remove", "id", id, "error", err)
	}
	
	// Remove directories
	upperDir := filepath.Join(d.upperDir, id)
	workDir := filepath.Join(d.workDir, id)
	mergedDir := filepath.Join(d.mergedDir, id)
	
	for _, dir := range []string{upperDir, workDir, mergedDir} {
		if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
			d.logger.Warn("Failed to remove directory", "dir", dir, "error", err)
		}
	}
	
	// Remove metadata
	metaFile := filepath.Join(d.config.GraphRoot, "overlay-layers", "metadata", id+".json")
	os.Remove(metaFile)
	
	d.logger.Info("Removed overlay layer", "id", id)
	return nil
}

// Exists checks if a layer exists
func (d *OverlayFSDriver) Exists(ctx context.Context, id string) (bool, error) {
	upperDir := filepath.Join(d.upperDir, id)
	_, err := os.Stat(upperDir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Status returns driver status
func (d *OverlayFSDriver) Status(ctx context.Context) (*StorageStatus, error) {
	status := &StorageStatus{
		Driver:        d.Name(),
		RootDir:       d.config.GraphRoot,
		BackingFs:     "overlayfs",
		SupportsDType: true,
		Status:        make(map[string]string),
	}
	
	// Get filesystem stats
	var stat syscall.Statfs_t
	if err := syscall.Statfs(d.config.GraphRoot, &stat); err == nil {
		status.Status["Available Space"] = fmt.Sprintf("%d", stat.Bavail*uint64(stat.Bsize))
		status.Status["Total Space"] = fmt.Sprintf("%d", stat.Blocks*uint64(stat.Bsize))
	}
	
	return status, nil
}

// Cleanup performs driver cleanup
func (d *OverlayFSDriver) Cleanup(ctx context.Context) error {
	d.logger.Info("Cleaning up OverlayFS driver")
	return nil
}

// Helper methods for OverlayFSDriver

func (d *OverlayFSDriver) saveLayerInfo(id string, info *StorageInfo) error {
	metaDir := filepath.Join(d.config.GraphRoot, "overlay-layers", "metadata")
	if err := os.MkdirAll(metaDir, 0700); err != nil {
		return err
	}
	
	metaFile := filepath.Join(metaDir, id+".json")
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	
	return os.WriteFile(metaFile, data, 0600)
}

func (d *OverlayFSDriver) getLayerInfo(id string) (*StorageInfo, error) {
	metaFile := filepath.Join(d.config.GraphRoot, "overlay-layers", "metadata", id+".json")
	data, err := os.ReadFile(metaFile)
	if err != nil {
		return nil, err
	}
	
	var info StorageInfo
	err = json.Unmarshal(data, &info)
	return &info, err
}

func (d *OverlayFSDriver) getLowerDirs(parentID string) ([]string, error) {
	var lowerDirs []string
	
	// Recursively collect parent layers
	currentID := parentID
	for currentID != "" {
		upperDir := filepath.Join(d.upperDir, currentID)
		if _, err := os.Stat(upperDir); err == nil {
			lowerDirs = append(lowerDirs, upperDir)
		}
		
		// Get parent of current layer
		info, err := d.getLayerInfo(currentID)
		if err != nil {
			break
		}
		currentID = info.ParentID
	}
	
	return lowerDirs, nil
}

// DeviceMapperDriver implements storage driver for Device Mapper
type DeviceMapperDriver struct {
	config          StorageDriverConfig
	logger          *slog.Logger
	poolName        string
	dataLoopback    string
	metadataLoopback string
	dataSize        uint64
	metadataSize    uint64
	baseFsSize      uint64
	filesystem      string
}

// Name returns the driver name
func (d *DeviceMapperDriver) Name() string {
	return "devicemapper"
}

// Init initializes the Device Mapper driver
func (d *DeviceMapperDriver) Init(ctx context.Context, config StorageDriverConfig) error {
	d.config = config
	d.logger = Logger(ctx).With("driver", "devicemapper")
	
	// Set defaults
	d.poolName = config.Options["dm.thinpool"]
	if d.poolName == "" {
		d.poolName = "gophertainer-thinpool"
	}
	
	d.dataSize = 100 * 1024 * 1024 * 1024 // 100GB default
	if sizeStr := config.Options["dm.datasize"]; sizeStr != "" {
		if size, err := parseSize(sizeStr); err == nil {
			d.dataSize = size
		}
	}
	
	d.metadataSize = 2 * 1024 * 1024 * 1024 // 2GB default
	if sizeStr := config.Options["dm.metadatasize"]; sizeStr != "" {
		if size, err := parseSize(sizeStr); err == nil {
			d.metadataSize = size
		}
	}
	
	d.baseFsSize = 10 * 1024 * 1024 * 1024 // 10GB default
	if sizeStr := config.Options["dm.basesize"]; sizeStr != "" {
		if size, err := parseSize(sizeStr); err == nil {
			d.baseFsSize = size
		}
	}
	
	d.filesystem = config.Options["dm.fs"]
	if d.filesystem == "" {
		d.filesystem = "ext4"
	}
	
	// Initialize device mapper components
	if err := d.initDeviceMapper(ctx); err != nil {
		return WrapStorageError("devicemapper_init", d.poolName, fmt.Errorf("failed to initialize device mapper: %w", err))
	}
	
	d.logger.Info("Device Mapper driver initialized",
		"pool", d.poolName,
		"data_size", d.dataSize,
		"metadata_size", d.metadataSize)
	
	return nil
}

// initDeviceMapper sets up the device mapper thin pool
func (d *DeviceMapperDriver) initDeviceMapper(ctx context.Context) error {
	// Check if device mapper is available
	if err := d.checkDeviceMapperSupport(ctx); err != nil {
		return err
	}
	
	// Set up loopback devices for data and metadata
	if err := d.setupLoopbackDevices(ctx); err != nil {
		return WrapStorageError("loopback_setup", "loopback_devices", fmt.Errorf("failed to setup loopback devices: %w", err))
	}
	
	// Create thin pool
	if err := d.createThinPool(ctx); err != nil {
		return WrapStorageError("thin_pool_create", d.poolName, fmt.Errorf("failed to create thin pool: %w", err))
	}
	
	return nil
}

// checkDeviceMapperSupport verifies device mapper support
func (d *DeviceMapperDriver) checkDeviceMapperSupport(ctx context.Context) error {
	// Check for dmsetup command
	if _, err := exec.LookPath("dmsetup"); err != nil {
		return WrapStorageError("dmsetup_missing", "dmsetup", fmt.Errorf("dmsetup command not found: %w", err))
	}
	
	// Check if device mapper module is loaded
	if _, err := os.Stat("/proc/devices"); err == nil {
		data, err := os.ReadFile("/proc/devices")
		if err == nil && strings.Contains(string(data), "device-mapper") {
			return nil
		}
	}
	
	// Try to load device mapper modules
	for _, module := range []string{"dm_mod", "dm_thin_pool"} {
		if err := exec.CommandContext(ctx, "modprobe", module).Run(); err != nil {
			return WrapStorageError("module_load", module, fmt.Errorf("failed to load module %s: %w", module, err))
		}
	}
	
	return nil
}

// setupLoopbackDevices creates loopback devices for data and metadata
func (d *DeviceMapperDriver) setupLoopbackDevices(ctx context.Context) error {
	dataDir := filepath.Join(d.config.GraphRoot, "devicemapper")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	
	// Create data loopback file
	dataFile := filepath.Join(dataDir, "data")
	if err := d.createSparseFile(dataFile, d.dataSize); err != nil {
		return WrapStorageError("data_file_create", dataFile, fmt.Errorf("failed to create data file: %w", err))
	}
	
	// Create metadata loopback file
	metadataFile := filepath.Join(dataDir, "metadata")
	if err := d.createSparseFile(metadataFile, d.metadataSize); err != nil {
		return WrapStorageError("metadata_file_create", metadataFile, fmt.Errorf("failed to create metadata file: %w", err))
	}
	
	// Setup loopback devices
	dataLoop, err := d.setupLoopback(ctx, dataFile)
	if err != nil {
		return WrapStorageError("data_loopback_setup", dataFile, fmt.Errorf("failed to setup data loopback: %w", err))
	}
	d.dataLoopback = dataLoop
	
	metadataLoop, err := d.setupLoopback(ctx, metadataFile)
	if err != nil {
		return WrapStorageError("metadata_loopback_setup", metadataFile, fmt.Errorf("failed to setup metadata loopback: %w", err))
	}
	d.metadataLoopback = metadataLoop
	
	return nil
}

// createSparseFile creates a sparse file of specified size
func (d *DeviceMapperDriver) createSparseFile(path string, size uint64) error {
	if _, err := os.Stat(path); err == nil {
		return nil // File already exists
	}
	
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	
	if err := file.Truncate(int64(size)); err != nil {
		return err
	}
	
	return nil
}

// setupLoopback creates a loopback device for a file
func (d *DeviceMapperDriver) setupLoopback(ctx context.Context, file string) (string, error) {
	cmd := exec.CommandContext(ctx, "losetup", "--find", "--show", file)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	
	return strings.TrimSpace(string(output)), nil
}

// createThinPool creates the device mapper thin pool
func (d *DeviceMapperDriver) createThinPool(ctx context.Context) error {
	// Check if pool already exists
	cmd := exec.CommandContext(ctx, "dmsetup", "info", d.poolName)
	if err := cmd.Run(); err == nil {
		return nil // Pool already exists
	}
	
	// Calculate pool size in sectors (512 bytes each)
	dataBlocks := d.dataSize / 4096    // 4KB blocks
	lowWaterMark := dataBlocks / 10     // 10% low water mark
	
	// Create thin pool table
	table := fmt.Sprintf("0 %d thin-pool %s %s %d %d",
		d.dataSize/512,
		d.dataLoopback,
		d.metadataLoopback,
		4096/512,     // Block size in sectors
		lowWaterMark)
	
	// Create the pool
	cmd = exec.CommandContext(ctx, "dmsetup", "create", d.poolName)
	cmd.Stdin = strings.NewReader(table)
	if err := cmd.Run(); err != nil {
		return WrapStorageError("thin_pool_dmsetup", d.poolName, fmt.Errorf("failed to create thin pool: %w", err))
	}
	
	return nil
}

// Create creates a new thin device
func (d *DeviceMapperDriver) Create(ctx context.Context, id string, parentID string, opts CreateOptions) (*StorageInfo, error) {
	deviceName := fmt.Sprintf("%s-%s", d.poolName, id)
	
	// Create thin device
	table := fmt.Sprintf("0 %d thin %s %s",
		d.baseFsSize/512,
		fmt.Sprintf("/dev/mapper/%s", d.poolName),
		id)
	
	cmd := exec.CommandContext(ctx, "dmsetup", "create", deviceName)
	cmd.Stdin = strings.NewReader(table)
	if err := cmd.Run(); err != nil {
		return nil, WrapStorageError("thin_device_create", deviceName, fmt.Errorf("failed to create thin device: %w", err))
	}
	
	// Create filesystem
	devicePath := fmt.Sprintf("/dev/mapper/%s", deviceName)
	if err := d.createFilesystem(ctx, devicePath); err != nil {
		return nil, WrapStorageError("filesystem_create", devicePath, fmt.Errorf("failed to create filesystem: %w", err))
	}
	
	info := &StorageInfo{
		ID:        id,
		ParentID:  parentID,
		Size:      int64(d.baseFsSize),
		Metadata:  make(map[string]string),
		Created:   time.Now(),
		Driver:    d.Name(),
	}
	
	info.Metadata["device_name"] = deviceName
	info.Metadata["device_path"] = devicePath
	
	d.logger.Info("Created device mapper device", "id", id, "device", deviceName)
	return info, nil
}

// createFilesystem creates a filesystem on the device
func (d *DeviceMapperDriver) createFilesystem(ctx context.Context, device string) error {
	var cmd *exec.Cmd
	switch d.filesystem {
	case "ext4":
		cmd = exec.CommandContext(ctx, "mkfs.ext4", "-F", device)
	case "xfs":
		cmd = exec.CommandContext(ctx, "mkfs.xfs", "-f", device)
	default:
		return WrapStorageError("filesystem_unsupported", d.filesystem, fmt.Errorf("unsupported filesystem: %s", d.filesystem))
	}
	
	return cmd.Run()
}

// Mount mounts the thin device
func (d *DeviceMapperDriver) Mount(ctx context.Context, id string, opts MountOptions) (string, error) {
	deviceName := fmt.Sprintf("%s-%s", d.poolName, id)
	devicePath := fmt.Sprintf("/dev/mapper/%s", deviceName)
	
	mountDir := filepath.Join(d.config.GraphRoot, "devicemapper", "mounts", id)
	if err := os.MkdirAll(mountDir, 0755); err != nil {
		return "", WrapStorageError("mount_dir_create", mountDir, fmt.Errorf("failed to create mount directory: %w", err))
	}
	
	// Mount the device
	var flags uintptr
	if !opts.ReadWrite {
		flags |= unix.MS_RDONLY
	}
	
	if err := unix.Mount(devicePath, mountDir, d.filesystem, flags, ""); err != nil {
		return "", WrapStorageError("device_mount", devicePath, fmt.Errorf("failed to mount device: %w", err))
	}
	
	d.logger.Info("Mounted device mapper device", "id", id, "path", mountDir)
	return mountDir, nil
}

// Unmount unmounts the thin device
func (d *DeviceMapperDriver) Unmount(ctx context.Context, id string) error {
	mountDir := filepath.Join(d.config.GraphRoot, "devicemapper", "mounts", id)
	
	if err := unix.Unmount(mountDir, 0); err != nil && !os.IsNotExist(err) {
		return WrapStorageError("device_unmount", mountDir, fmt.Errorf("failed to unmount device: %w", err))
	}
	
	d.logger.Info("Unmounted device mapper device", "id", id)
	return nil
}

// Remove removes the thin device
func (d *DeviceMapperDriver) Remove(ctx context.Context, id string) error {
	deviceName := fmt.Sprintf("%s-%s", d.poolName, id)
	
	// Unmount first
	if err := d.Unmount(ctx, id); err != nil {
		d.logger.Warn("Failed to unmount before remove", "id", id, "error", err)
	}
	
	// Remove device
	cmd := exec.CommandContext(ctx, "dmsetup", "remove", deviceName)
	if err := cmd.Run(); err != nil {
		return WrapStorageError("thin_device_remove", deviceName, fmt.Errorf("failed to remove thin device: %w", err))
	}
	
	// Remove mount directory
	mountDir := filepath.Join(d.config.GraphRoot, "devicemapper", "mounts", id)
	os.RemoveAll(mountDir)
	
	d.logger.Info("Removed device mapper device", "id", id)
	return nil
}

// Exists checks if a thin device exists
func (d *DeviceMapperDriver) Exists(ctx context.Context, id string) (bool, error) {
	deviceName := fmt.Sprintf("%s-%s", d.poolName, id)
	
	cmd := exec.CommandContext(ctx, "dmsetup", "info", deviceName)
	err := cmd.Run()
	return err == nil, nil
}

// Status returns driver status
func (d *DeviceMapperDriver) Status(ctx context.Context) (*StorageStatus, error) {
	status := &StorageStatus{
		Driver:        d.Name(),
		RootDir:       d.config.GraphRoot,
		BackingFs:     "devicemapper",
		SupportsDType: true,
		Status:        make(map[string]string),
	}
	
	status.Status["Pool Name"] = d.poolName
	status.Status["Data Loopback"] = d.dataLoopback
	status.Status["Metadata Loopback"] = d.metadataLoopback
	status.Status["Data Size"] = fmt.Sprintf("%d", d.dataSize)
	status.Status["Metadata Size"] = fmt.Sprintf("%d", d.metadataSize)
	status.Status["Base FS Size"] = fmt.Sprintf("%d", d.baseFsSize)
	status.Status["Filesystem"] = d.filesystem
	
	return status, nil
}

// Cleanup performs driver cleanup
func (d *DeviceMapperDriver) Cleanup(ctx context.Context) error {
	d.logger.Info("Cleaning up Device Mapper driver")
	
	// Remove thin pool
	if d.poolName != "" {
		cmd := exec.CommandContext(ctx, "dmsetup", "remove", d.poolName)
		cmd.Run() // Ignore errors during cleanup
	}
	
	// Remove loopback devices
	if d.dataLoopback != "" {
		cmd := exec.CommandContext(ctx, "losetup", "--detach", d.dataLoopback)
		cmd.Run()
	}
	if d.metadataLoopback != "" {
		cmd := exec.CommandContext(ctx, "losetup", "--detach", d.metadataLoopback)
		cmd.Run()
	}
	
	return nil
}

// Helper functions

// parseSize parses a size string like "100GB", "2TB", etc.
func parseSize(sizeStr string) (uint64, error) {
	re := regexp.MustCompile(`^(\d+)\s*([KMGT]?B?)$`)
	matches := re.FindStringSubmatch(strings.ToUpper(sizeStr))
	if len(matches) != 3 {
		return 0, WrapStorageError("size_parse", sizeStr, fmt.Errorf("invalid size format: %s", sizeStr))
	}
	
	size, err := strconv.ParseUint(matches[1], 10, 64)
	if err != nil {
		return 0, err
	}
	
	unit := matches[2]
	switch unit {
	case "K", "KB":
		size *= 1024
	case "M", "MB":
		size *= 1024 * 1024
	case "G", "GB":
		size *= 1024 * 1024 * 1024
	case "T", "TB":
		size *= 1024 * 1024 * 1024 * 1024
	}
	
	return size, nil
}