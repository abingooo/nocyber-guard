<script setup lang="ts">
import { CheckCircle2, Info, X, XCircle } from 'lucide-vue-next'
import { useToast } from '@/composables/toast'

const { messages, dismiss } = useToast()
</script>

<template>
  <div class="toast-viewport" aria-live="polite">
    <TransitionGroup name="toast">
      <div v-for="message in messages" :key="message.id" class="toast-message" :class="`toast-${message.tone}`">
        <CheckCircle2 v-if="message.tone === 'success'" :size="18" />
        <XCircle v-else-if="message.tone === 'error'" :size="18" />
        <Info v-else :size="18" />
        <div><strong>{{ message.title }}</strong><span v-if="message.detail">{{ message.detail }}</span></div>
        <button class="toast-close" aria-label="关闭提示" @click="dismiss(message.id)"><X :size="15" /></button>
      </div>
    </TransitionGroup>
  </div>
</template>
