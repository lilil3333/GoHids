import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'
import Home from '../views/Home.vue'
import Agents from '../views/Agents.vue'
import Alerts from '../views/Alerts.vue'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login
  },
  {
    path: '/',
    component: Dashboard,
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Home',
        component: Home
      },
      {
        path: 'agents',
        name: 'Agents',
        component: Agents
      },
      {
        path: 'alerts',
        name: 'Alerts',
        component: Alerts
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, _from, next) => {
  const token = localStorage.getItem('token')
  if (to.name !== 'Login' && !token) {
    next({ name: 'Login' })
  } else {
    next()
  }
})

export default router
