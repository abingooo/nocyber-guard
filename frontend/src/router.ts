import { createRouter, createWebHistory } from 'vue-router'
import { useAuth } from '@/auth'
import LoginView from '@/views/LoginView.vue'
import OverviewView from '@/views/OverviewView.vue'
import EventsView from '@/views/EventsView.vue'
import HashLibraryView from '@/views/HashLibraryView.vue'
import ClientRulesView from '@/views/ClientRulesView.vue'
import SettingsView from '@/views/SettingsView.vue'
import AppShell from '@/components/AppShell.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: LoginView, meta: { public: true } },
    {
      path: '/',
      component: AppShell,
      children: [
        { path: '', name: 'overview', component: OverviewView },
        { path: 'events', name: 'events', component: EventsView },
        {
          path: 'trusted',
          name: 'trusted',
          component: HashLibraryView,
          props: { kind: 'trusted' },
        },
        {
          path: 'risks',
          name: 'risks',
          component: HashLibraryView,
          props: { kind: 'risk' },
        },
        { path: 'clients', name: 'clients', component: ClientRulesView },
        { path: 'settings', name: 'settings', component: SettingsView },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuth()
  if (to.meta.public) {
    if (to.name === 'login' && auth.authenticated.value) return { name: 'overview' }
    return true
  }
  if (!auth.authenticated.value || !(await auth.verify())) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  return true
})
