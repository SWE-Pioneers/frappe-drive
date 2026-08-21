<template>
  <div class="h-full w-full flex flex-col">
    <div v-if="error" class="m-auto max-w-md text-center px-6">
      <div class="text-lg font-medium text-ink-gray-8">
        {{ __("This document could not be opened") }}
      </div>
      <p class="mt-2 text-sm text-ink-gray-6">{{ error }}</p>
      <Button class="mt-4" @click="$router.back()">{{ __("Go back") }}</Button>
    </div>

    <div v-else-if="loading" class="m-auto text-sm text-ink-gray-6">
      {{ __("Opening in LibreOffice…") }}
    </div>

    <!--
      The token is POSTed, never put in the URL: a WOPI access token in a query string ends up in
      browser history, proxy logs and the Referer of every request the editor makes. The form
      targets the iframe below, so the editor loads inside the page.
    -->
    <form
      v-show="!loading && !error"
      ref="launchForm"
      :action="action"
      method="post"
      target="collabora-frame"
      class="hidden"
    >
      <input type="hidden" name="access_token" :value="cfg?.token" />
      <input type="hidden" name="access_token_ttl" :value="cfg?.token_ttl" />
    </form>

    <iframe
      v-show="!loading && !error"
      name="collabora-frame"
      class="w-full h-full border-0"
      allow="clipboard-read; clipboard-write; fullscreen"
      :title="cfg?.title || __('Document')"
    />
  </div>
</template>

<script setup>
import { ref, onMounted, nextTick } from "vue"
import { Button, createResource } from "frappe-ui"
import { buildEditorAction } from "@/utils/office"

const props = defineProps({ entityName: String })

const cfg = ref(null)
const action = ref("")
const error = ref("")
const loading = ref(true)
const launchForm = ref(null)

const editorConfig = createResource({
  url: "drive.api.wopi_host.get_editor_config",
  makeParams: () => ({ entity_name: props.entityName }),
})

onMounted(async () => {
  try {
    const data = await editorConfig.submit()
    cfg.value = data
    action.value = buildEditorAction(data)
    loading.value = false
    // The form has to exist in the DOM before it can be submitted, and v-show only renders it once
    // `loading` is false — hence the tick.
    await nextTick()
    launchForm.value?.submit()
  } catch (e) {
    // The backend throws with a readable reason (no permission, unsupported type, Collabora not
    // reachable from a browser). Surface it rather than leaving a blank iframe, which is exactly
    // the failure mode that made this integration hard to debug in the first place.
    error.value = e?.messages?.[0] || e?.message || __("Unknown error")
    loading.value = false
  }
})
</script>
