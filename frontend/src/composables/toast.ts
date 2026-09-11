import { computed, ref } from 'vue'

export interface ToastMessage {
  id: number
  title: string
  detail?: string
  tone: 'success' | 'error' | 'info'
}

const messages = ref<ToastMessage[]>([])
let nextID = 1

export function useToast() {
  function show(title: string, options: { detail?: string; tone?: ToastMessage['tone'] } = {}) {
    const id = nextID++
    messages.value.push({ id, title, detail: options.detail, tone: options.tone || 'success' })
    window.setTimeout(() => dismiss(id), 3800)
  }

  function dismiss(id: number) {
    messages.value = messages.value.filter((message) => message.id !== id)
  }

  return { messages: computed(() => messages.value), show, dismiss }
}
