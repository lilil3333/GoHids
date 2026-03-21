//go:build windows
// +build windows

package collector

import (
	"fmt"
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"time"

	"golang.org/x/sys/windows/registry"
)

type RegistryCollector struct {
	stopCh chan struct{}
	// cache: KeyPath -> (ValueName -> ValueData)
	cache map[string]map[string]string
}

func NewRegistryCollector() *RegistryCollector {
	return &RegistryCollector{
		stopCh: make(chan struct{}),
		cache:  make(map[string]map[string]string),
	}
}

func (c *RegistryCollector) Name() string {
	return "Registry"
}

// RegistryKeyDefinition 定义要监控的根键和子路径
type RegistryKeyDefinition struct {
	Root registry.Key
	Path string
	Name string // 用于日志显示的友好名称
}

func (c *RegistryCollector) Start(ch chan<- *pb.RawData) {
	// 定义要监控的注册表项
	// 注意：服务模式下 CURRENT_USER 是 SYSTEM 用户，可能无法监控到登录用户的启动项
	// 生产环境通常需要遍历 HKEY_USERS
	monitorKeys := []RegistryKeyDefinition{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM_Run"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM_RunOnce"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "HKLM_WOW6432_Run"},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, "HKCU_Run"},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "HKCU_RunOnce"},
	}

	// 初始化缓存
	c.refreshCache(monitorKeys, nil) // nil ch means don't report, just init

	ticker := time.NewTicker(10 * time.Second) // 加快检测频率用于演示
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.refreshCache(monitorKeys, ch)
		}
	}
}

func (c *RegistryCollector) Stop() {
	close(c.stopCh)
}

func (c *RegistryCollector) refreshCache(keys []RegistryKeyDefinition, ch chan<- *pb.RawData) {
	for _, def := range keys {
		currentItems, err := c.readKeyItems(def.Root, def.Path)
		if err != nil {
			// 某些键可能不存在（例如 RunOnce 经常是空的或不存在），忽略错误
			continue
		}

		// 获取该 Key 的旧缓存
		cacheKey := def.Name
		oldItems := c.cache[cacheKey]
		if oldItems == nil {
			oldItems = make(map[string]string)
		}

		// 1. 检查新增和修改
		for name, val := range currentItems {
			oldVal, exists := oldItems[name]
			if !exists {
				// 新增
				if ch != nil {
					c.sendEvent(ch, "ADDED", def.Path, name, val)
				}
			} else if oldVal != val {
				// 修改
				if ch != nil {
					c.sendEvent(ch, "MODIFIED", def.Path, name, fmt.Sprintf("%s -> %s", oldVal, val))
				}
			}
		}

		// 2. 检查删除
		for name, val := range oldItems {
			if _, exists := currentItems[name]; !exists {
				// 删除
				if ch != nil {
					c.sendEvent(ch, "DELETED", def.Path, name, val)
				}
			}
		}

		// 更新缓存
		c.cache[cacheKey] = currentItems
	}
}

// readKeyItems 读取指定注册表键下的所有 Name:Value
func (c *RegistryCollector) readKeyItems(root registry.Key, path string) (map[string]string, error) {
	k, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	items := make(map[string]string)
	for _, name := range names {
		// 尝试读取字符串值
		val, _, err := k.GetStringValue(name)
		if err != nil {
			// 如果不是字符串，尝试读取为二进制或其他，这里简化处理，只监控字符串类型的启动项
			// 某些启动项可能是 ExpandString
			valExpand, _, err2 := k.GetStringValue(name) // GetStringValue handles ExpandString too normally?
			// Actually registry package has GetStringValue for REG_SZ and REG_EXPAND_SZ
			if err2 == nil {
				val = valExpand
			} else {
				val = "<non-string-value>"
			}
		}
		items[name] = val
	}
	return items, nil
}

func (c *RegistryCollector) sendEvent(ch chan<- *pb.RawData, eventType, key, name, value string) {
	log.Printf("[Registry] %s: %s\\%s = %s", eventType, key, name, value)
	data := createRawData(common.DataTypeRegistry, map[string]string{
		"event": eventType,
		"key":   key,
		"name":  name,
		"value": value,
	})
	data.Data[0].Timestamp = time.Now().Unix()
	ch <- data
}
