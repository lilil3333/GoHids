package collector

import (
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

type FileCollector struct {
	path   string
	stopCh chan struct{}
}

func NewFileCollector(path string) *FileCollector {
	return &FileCollector{
		path:   path,
		stopCh: make(chan struct{}),
	}
}

func (c *FileCollector) Name() string {
	return "File"
}

func (c *FileCollector) Start(ch chan<- *pb.RawData) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Println("Fsnotify error:", err)
		return
	}
	// Do not defer watcher.Close() here if we want it to run in background, 
	// but we are in a goroutine (called by StartAll -> go Start), so it's fine.
	// Actually StartAll uses go routines? Let's check manager.
	// Assuming Start is blocking or long running.
	// Wait, if Start is blocking, we should defer.
	defer watcher.Close()

	// Recursive Add
	err = filepath.Walk(c.path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip hidden directories (optional)
			if strings.HasPrefix(info.Name(), ".") && path != c.path {
				return filepath.SkipDir
			}
			err = watcher.Add(path)
			if err != nil {
				log.Printf("Fsnotify add error for %s: %v", path, err)
			} else {
				// log.Printf("Watching dir: %s", path) // Too noisy for recursive
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Error walking path %s: %v", c.path, err)
	}
	
	log.Printf("Monitoring directory (recursive): %s", c.path)

	for {
		select {
		case <-c.stopCh:
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			
			// If a new directory is created, watch it
			if event.Op&fsnotify.Create == fsnotify.Create {
				fi, err := os.Stat(event.Name)
				if err == nil && fi.IsDir() {
					watcher.Add(event.Name)
					log.Printf("Added new directory to watch: %s", event.Name)
				}
			}

			// Filter out too many events
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create ||
				event.Op&fsnotify.Remove == fsnotify.Remove || event.Op&fsnotify.Rename == fsnotify.Rename {
				log.Println("File event:", event)

				fields := map[string]string{
					"event": event.Op.String(),
					"name":  event.Name,
				}

				if event.Op&fsnotify.Rename == fsnotify.Rename {
					fields["old_name"] = "" 
				}

				data := createRawData(common.DataTypeFile, fields)
				data.Data[0].Timestamp = time.Now().Unix()
				ch <- data
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("error:", err)
		}
	}
}

func (c *FileCollector) Stop() {
	close(c.stopCh)
}
