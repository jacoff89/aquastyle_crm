<script setup>
defineProps({
    /** Названия упражнений программы, которые клиенту осталось пройти, в порядке настроек. */
    exercises: { type: Array, required: true },
    /** Сколько всего упражнений в программе. */
    total: { type: Number, required: true },
});
</script>

<template>
    <div class="mt-2">
        <details v-if="exercises.length" class="group">
            <summary class="inline-flex cursor-pointer list-none items-center gap-1 text-xs text-muted hover:text-ink [&::-webkit-details-marker]:hidden">
                <svg class="size-3 transition-transform group-open:rotate-90" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 0 1 .02-1.06L11.17 10 7.23 6.29a.75.75 0 1 1 1.04-1.08l4.5 4.25a.75.75 0 0 1 0 1.08l-4.5 4.25a.75.75 0 0 1-1.06-.02Z" clip-rule="evenodd" />
                </svg>
                Осталось пройти: {{ exercises.length }} из {{ total }}
            </summary>
            <ul class="mt-1 flex flex-wrap gap-1.5" aria-label="Осталось пройти">
                <li v-for="exercise in exercises" :key="exercise" class="rounded-full border border-line px-2.5 py-0.5 text-xs text-muted">
                    {{ exercise }}
                </li>
            </ul>
        </details>
        <p v-else class="text-xs font-medium text-emerald-800">Все упражнения программы пройдены</p>
    </div>
</template>
