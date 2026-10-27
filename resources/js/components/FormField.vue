<script setup>
defineProps({
    id: { type: String, required: true },
    label: { type: String, required: true },
    error: { type: String, default: '' },
    hint: { type: String, default: '' },
});
</script>

<template>
    <div class="space-y-1.5">
        <label :for="id" class="block text-sm font-medium text-ink">{{ label }}</label>
        <slot />
        <p v-if="error" :id="`${id}-error`" class="text-sm text-flag">{{ error }}</p>
        <p v-else-if="hint" class="text-sm text-muted">{{ hint }}</p>
    </div>
</template>
