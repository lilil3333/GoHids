package api

import (
	"gohids/internal/server/repository"
	"gohids/internal/server/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Run(addr string, svc service.AgentService, repo repository.Repository) {
	r := gin.Default()

	// CORS Middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// --- Public Routes ---

	// Login API
	r.POST("/api/login", func(c *gin.Context) {
		var loginReq struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&loginReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Invalid parameters: " + err.Error()})
			return
		}

		token, err := svc.Login(loginReq.Username, loginReq.Password)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 401,
				"msg":  "Invalid username or password",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"code":  0,
			"msg":   "success",
			"token": token,
		})
	})

	// --- Protected Routes ---
	// All routes below this line require valid JWT
	authorized := r.Group("/api")
	authorized.Use(JWTAuthMiddleware())
	{
		authorized.GET("/dashboard/stats", func(c *gin.Context) {
			stats, err := svc.GetDashboardStats()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": 0, "data": stats})
		})

		// Asset APIs
		authorized.GET("/assets/ports", func(c *gin.Context) {
			agentID := c.Query("agent_id")
			ports, err := svc.GetAssetPorts(agentID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": 0, "data": ports})
		})

		authorized.GET("/assets/users", func(c *gin.Context) {
			agentID := c.Query("agent_id")
			users, err := svc.GetAssetUsers(agentID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": 0, "data": users})
		})

		authorized.GET("/assets/changes", func(c *gin.Context) {
			agentID := c.Query("agent_id")
			changes, err := svc.GetAssetChanges(agentID, 100)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": 0, "data": changes})
		})

		authorized.GET("/agents", func(c *gin.Context) {
			list := svc.GetAllAgentsStatus()
			c.JSON(http.StatusOK, gin.H{
				"code": 0,
				"data": list,
			})
		})

		authorized.GET("/agent/:id", func(c *gin.Context) {
			id := c.Param("id")
			if info, ok := svc.GetAgentStatus(id); ok {
				c.JSON(http.StatusOK, gin.H{"code": 0, "data": info})
			} else {
				c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "not found"})
			}
		})

		// Get Alerts
		authorized.GET("/alerts", func(c *gin.Context) {
			alerts, err := repo.GetAlerts(100)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": 0, "data": alerts})
		})

		// Export Security Events
		authorized.GET("/export/events", func(c *gin.Context) {
			agentID := c.Query("agent_id")
			events, err := repo.GetSecurityEvents(agentID, 1000)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}

			c.Header("Content-Disposition", "attachment; filename=security_events.json")
			c.JSON(http.StatusOK, events)
		})

		// Export Alerts
		authorized.GET("/export/alerts", func(c *gin.Context) {
			alerts, err := repo.GetAlerts(1000)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}

			c.Header("Content-Disposition", "attachment; filename=alerts.json")
			c.JSON(http.StatusOK, alerts)
		})

		// --- Timeline / Investigation APIs ---

		// Get Process Events (Timeline)
		authorized.GET("/events/process", func(c *gin.Context) {
			agentID := c.Query("agent_id")
			limit := 100 // Default limit
			events, err := svc.GetProcessEvents(agentID, limit)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": 0, "data": events})
		})

		// Get Network Events (Timeline)
		authorized.GET("/events/network", func(c *gin.Context) {
			agentID := c.Query("agent_id")
			limit := 100
			events, err := svc.GetNetworkEvents(agentID, limit)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": 0, "data": events})
		})

		// Get File Events (Timeline)
		authorized.GET("/events/file", func(c *gin.Context) {
			agentID := c.Query("agent_id")
			limit := 100
			events, err := svc.GetFileEvents(agentID, limit)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "msg": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"code": 0, "data": events})
		})

		// --- System Config ---
		authorized.GET("/config/threatbook", func(c *gin.Context) {
			enabled := svc.IsThreatBookEnabled()
			c.JSON(http.StatusOK, gin.H{"code": 0, "enabled": enabled})
		})

		authorized.POST("/config/threatbook", func(c *gin.Context) {
			var req struct {
				Enabled bool `json:"enabled"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "Invalid parameters"})
				return
			}
			svc.SetThreatBookEnabled(req.Enabled)
			c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "success", "enabled": req.Enabled})
		})
	}

	r.Run(addr)
}
