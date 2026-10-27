<script setup>
import { usePage } from '@inertiajs/vue3';
import AppLogo from '../components/AppLogo.vue';

defineProps({
    title: { type: String, required: true },
    description: { type: String, default: '' },
});

const page = usePage();
</script>

<template>
    <div class="flex min-h-full flex-col">
        <main class="flex flex-1 justify-center px-4 py-10 sm:py-16">
            <div class="w-full max-w-md">
                <div class="mb-10 w-56"><AppLogo /></div>
                <p class="sr-only">{{ page.props.appName }}</p>

                <h1 class="text-2xl font-semibold tracking-tight text-ink">{{ title }}</h1>
                <p v-if="description" class="mt-2 text-sm leading-6 text-muted">{{ description }}</p>

                <div class="mt-8">
                    <slot />
                </div>
            </div>
        </main>
    </div>
</template>
