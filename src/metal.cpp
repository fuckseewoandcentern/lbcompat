#include "host.hpp"
#include "spirv_tri.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <vulkan/vulkan.h>

namespace lb {
namespace {

struct Gpu {
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice phys = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue queue = VK_NULL_HANDLE;
    uint32_t family = 0;
    VkCommandPool pool = VK_NULL_HANDLE;
    VkRenderPass pass = VK_NULL_HANDLE;
    VkPipelineLayout layout = VK_NULL_HANDLE;
    VkPipeline pipeline = VK_NULL_HANDLE;
    bool ok = false;

    void shutdown() {
        if (device) {
            vkDeviceWaitIdle(device);
            if (pipeline) vkDestroyPipeline(device, pipeline, nullptr);
            if (layout) vkDestroyPipelineLayout(device, layout, nullptr);
            if (pass) vkDestroyRenderPass(device, pass, nullptr);
            if (pool) vkDestroyCommandPool(device, pool, nullptr);
            vkDestroyDevice(device, nullptr);
        }
        if (instance) vkDestroyInstance(instance, nullptr);
        instance = VK_NULL_HANDLE;
        device = VK_NULL_HANDLE;
        ok = false;
    }

    bool init(std::string& err) {
        if (ok) return true;
        VkApplicationInfo app {VK_STRUCTURE_TYPE_APPLICATION_INFO};
        app.pApplicationName = "lbcompat";
        app.apiVersion = VK_API_VERSION_1_0;
        VkInstanceCreateInfo ici {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
        ici.pApplicationInfo = &app;
        VkResult vr = vkCreateInstance(&ici, nullptr, &instance);
        if (vr != VK_SUCCESS) {
            err = "vkCreateInstance failed";
            return false;
        }
        uint32_t ndev = 0;
        vkEnumeratePhysicalDevices(instance, &ndev, nullptr);
        if (!ndev) {
            err = "no vulkan device";
            return false;
        }
        std::vector<VkPhysicalDevice> devs(ndev);
        vkEnumeratePhysicalDevices(instance, &ndev, devs.data());
        phys = devs[0];
        for (VkPhysicalDevice d : devs) {
            VkPhysicalDeviceProperties props {};
            vkGetPhysicalDeviceProperties(d, &props);
            std::string name = props.deviceName;
            if (name.find("llvmpipe") != std::string::npos || name.find("lavapipe") != std::string::npos) {
                phys = d;
                break;
            }
        }
        uint32_t nq = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(phys, &nq, nullptr);
        std::vector<VkQueueFamilyProperties> qf(nq);
        vkGetPhysicalDeviceQueueFamilyProperties(phys, &nq, qf.data());
        family = 0;
        bool found = false;
        for (uint32_t i = 0; i < nq; ++i) {
            if (qf[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) {
                family = i;
                found = true;
                break;
            }
        }
        if (!found) {
            err = "no graphics queue";
            return false;
        }
        float prio = 1;
        VkDeviceQueueCreateInfo qci {VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
        qci.queueFamilyIndex = family;
        qci.queueCount = 1;
        qci.pQueuePriorities = &prio;
        VkDeviceCreateInfo dci {VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
        dci.queueCreateInfoCount = 1;
        dci.pQueueCreateInfos = &qci;
        vr = vkCreateDevice(phys, &dci, nullptr, &device);
        if (vr != VK_SUCCESS) {
            err = "vkCreateDevice failed";
            return false;
        }
        vkGetDeviceQueue(device, family, 0, &queue);
        VkCommandPoolCreateInfo pci {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
        pci.queueFamilyIndex = family;
        pci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
        if (vkCreateCommandPool(device, &pci, nullptr, &pool) != VK_SUCCESS) {
            err = "command pool";
            return false;
        }
        VkAttachmentDescription att {};
        att.format = VK_FORMAT_R8G8B8A8_UNORM;
        att.samples = VK_SAMPLE_COUNT_1_BIT;
        att.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
        att.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
        att.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
        att.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
        att.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
        att.finalLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
        VkAttachmentReference ref {0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
        VkSubpassDescription sub {};
        sub.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
        sub.colorAttachmentCount = 1;
        sub.pColorAttachments = &ref;
        VkRenderPassCreateInfo rp {VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO};
        rp.attachmentCount = 1;
        rp.pAttachments = &att;
        rp.subpassCount = 1;
        rp.pSubpasses = &sub;
        if (vkCreateRenderPass(device, &rp, nullptr, &pass) != VK_SUCCESS) {
            err = "render pass";
            return false;
        }
        VkShaderModuleCreateInfo vsi {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
        vsi.codeSize = kTriVert_count * 4;
        vsi.pCode = kTriVert;
        VkShaderModule vs = VK_NULL_HANDLE, fs = VK_NULL_HANDLE;
        if (vkCreateShaderModule(device, &vsi, nullptr, &vs) != VK_SUCCESS) {
            err = "vertex shader";
            return false;
        }
        VkShaderModuleCreateInfo fsi {VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
        fsi.codeSize = kTriFrag_count * 4;
        fsi.pCode = kTriFrag;
        if (vkCreateShaderModule(device, &fsi, nullptr, &fs) != VK_SUCCESS) {
            vkDestroyShaderModule(device, vs, nullptr);
            err = "fragment shader";
            return false;
        }
        VkPipelineLayoutCreateInfo pl {VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
        if (vkCreatePipelineLayout(device, &pl, nullptr, &layout) != VK_SUCCESS) {
            err = "pipeline layout";
            return false;
        }
        VkPipelineShaderStageCreateInfo stages[2] {};
        stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
        stages[0].module = vs;
        stages[0].pName = "main";
        stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
        stages[1].module = fs;
        stages[1].pName = "main";
        VkPipelineVertexInputStateCreateInfo vi {VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO};
        VkPipelineInputAssemblyStateCreateInfo ia {VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO};
        ia.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
        VkPipelineViewportStateCreateInfo vp {VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO};
        vp.viewportCount = 1;
        vp.scissorCount = 1;
        VkPipelineRasterizationStateCreateInfo rs {VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO};
        rs.polygonMode = VK_POLYGON_MODE_FILL;
        rs.cullMode = VK_CULL_MODE_NONE;
        rs.frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE;
        rs.lineWidth = 1;
        VkPipelineMultisampleStateCreateInfo ms {VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO};
        ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;
        VkPipelineColorBlendAttachmentState blend {};
        blend.colorWriteMask = 0xf;
        VkPipelineColorBlendStateCreateInfo cb {VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO};
        cb.attachmentCount = 1;
        cb.pAttachments = &blend;
        VkDynamicState dyn_states[2] = {VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR};
        VkPipelineDynamicStateCreateInfo dyn {VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO};
        dyn.dynamicStateCount = 2;
        dyn.pDynamicStates = dyn_states;
        VkGraphicsPipelineCreateInfo gp {VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO};
        gp.stageCount = 2;
        gp.pStages = stages;
        gp.pVertexInputState = &vi;
        gp.pInputAssemblyState = &ia;
        gp.pViewportState = &vp;
        gp.pRasterizationState = &rs;
        gp.pMultisampleState = &ms;
        gp.pColorBlendState = &cb;
        gp.pDynamicState = &dyn;
        gp.layout = layout;
        gp.renderPass = pass;
        vr = vkCreateGraphicsPipelines(device, VK_NULL_HANDLE, 1, &gp, nullptr, &pipeline);
        vkDestroyShaderModule(device, vs, nullptr);
        vkDestroyShaderModule(device, fs, nullptr);
        if (vr != VK_SUCCESS) {
            err = "pipeline";
            return false;
        }
        ok = true;
        return true;
    }

    uint32_t mem_type(uint32_t bits, VkMemoryPropertyFlags want) {
        VkPhysicalDeviceMemoryProperties mp {};
        vkGetPhysicalDeviceMemoryProperties(phys, &mp);
        for (uint32_t i = 0; i < mp.memoryTypeCount; ++i) {
            if ((bits & (1u << i)) && (mp.memoryTypes[i].propertyFlags & want) == want) return i;
        }
        return 0xffffffffu;
    }

    bool draw(int w, int h, float cr, float cg, float cb, float ca, bool triangle, std::vector<uint8_t>& pixels, std::string& err) {
        if (!init(err)) return false;
        if (w < 1) w = 1;
        if (h < 1) h = 1;
        VkImageCreateInfo ii {VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO};
        ii.imageType = VK_IMAGE_TYPE_2D;
        ii.format = VK_FORMAT_R8G8B8A8_UNORM;
        ii.extent = {static_cast<uint32_t>(w), static_cast<uint32_t>(h), 1};
        ii.mipLevels = 1;
        ii.arrayLayers = 1;
        ii.samples = VK_SAMPLE_COUNT_1_BIT;
        ii.tiling = VK_IMAGE_TILING_OPTIMAL;
        ii.usage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT;
        ii.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
        VkImage image = VK_NULL_HANDLE;
        if (vkCreateImage(device, &ii, nullptr, &image) != VK_SUCCESS) {
            err = "image";
            return false;
        }
        VkMemoryRequirements req {};
        vkGetImageMemoryRequirements(device, image, &req);
        uint32_t mt = mem_type(req.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
        if (mt == 0xffffffffu) mt = mem_type(req.memoryTypeBits, 0);
        VkMemoryAllocateInfo mai {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
        mai.allocationSize = req.size;
        mai.memoryTypeIndex = mt;
        VkDeviceMemory mem = VK_NULL_HANDLE;
        if (vkAllocateMemory(device, &mai, nullptr, &mem) != VK_SUCCESS) {
            vkDestroyImage(device, image, nullptr);
            err = "image memory";
            return false;
        }
        vkBindImageMemory(device, image, mem, 0);
        VkImageViewCreateInfo vi {VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO};
        vi.image = image;
        vi.viewType = VK_IMAGE_VIEW_TYPE_2D;
        vi.format = VK_FORMAT_R8G8B8A8_UNORM;
        vi.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        vi.subresourceRange.levelCount = 1;
        vi.subresourceRange.layerCount = 1;
        VkImageView view = VK_NULL_HANDLE;
        vkCreateImageView(device, &vi, nullptr, &view);
        VkFramebufferCreateInfo fi {VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO};
        fi.renderPass = pass;
        fi.attachmentCount = 1;
        fi.pAttachments = &view;
        fi.width = static_cast<uint32_t>(w);
        fi.height = static_cast<uint32_t>(h);
        fi.layers = 1;
        VkFramebuffer fb = VK_NULL_HANDLE;
        vkCreateFramebuffer(device, &fi, nullptr, &fb);
        VkBufferCreateInfo bi {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
        bi.size = static_cast<VkDeviceSize>(w) * h * 4;
        bi.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
        VkBuffer buf = VK_NULL_HANDLE;
        vkCreateBuffer(device, &bi, nullptr, &buf);
        vkGetBufferMemoryRequirements(device, buf, &req);
        mt = mem_type(req.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        mai.allocationSize = req.size;
        mai.memoryTypeIndex = mt;
        VkDeviceMemory bmem = VK_NULL_HANDLE;
        if (vkAllocateMemory(device, &mai, nullptr, &bmem) != VK_SUCCESS) {
            err = "readback memory";
            vkDestroyBuffer(device, buf, nullptr);
            vkDestroyFramebuffer(device, fb, nullptr);
            vkDestroyImageView(device, view, nullptr);
            vkDestroyImage(device, image, nullptr);
            vkFreeMemory(device, mem, nullptr);
            return false;
        }
        vkBindBufferMemory(device, buf, bmem, 0);
        VkCommandBufferAllocateInfo ai {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
        ai.commandPool = pool;
        ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount = 1;
        VkCommandBuffer cmd = VK_NULL_HANDLE;
        vkAllocateCommandBuffers(device, &ai, &cmd);
        VkCommandBufferBeginInfo begin {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(cmd, &begin);
        VkClearValue clear {};
        clear.color.float32[0] = cr;
        clear.color.float32[1] = cg;
        clear.color.float32[2] = cb;
        clear.color.float32[3] = ca;
        VkRenderPassBeginInfo rbi {VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO};
        rbi.renderPass = pass;
        rbi.framebuffer = fb;
        rbi.renderArea.extent = {static_cast<uint32_t>(w), static_cast<uint32_t>(h)};
        rbi.clearValueCount = 1;
        rbi.pClearValues = &clear;
        vkCmdBeginRenderPass(cmd, &rbi, VK_SUBPASS_CONTENTS_INLINE);
        if (triangle && pipeline) {
            vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline);
            VkViewport viewport {};
            viewport.width = static_cast<float>(w);
            viewport.height = static_cast<float>(h);
            viewport.minDepth = 0;
            viewport.maxDepth = 1;
            VkRect2D scissor {};
            scissor.extent = {static_cast<uint32_t>(w), static_cast<uint32_t>(h)};
            vkCmdSetViewport(cmd, 0, 1, &viewport);
            vkCmdSetScissor(cmd, 0, 1, &scissor);
            vkCmdDraw(cmd, 3, 1, 0, 0);
        }
        vkCmdEndRenderPass(cmd);
        VkBufferImageCopy region {};
        region.imageSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        region.imageSubresource.layerCount = 1;
        region.imageExtent = {static_cast<uint32_t>(w), static_cast<uint32_t>(h), 1};
        vkCmdCopyImageToBuffer(cmd, image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, buf, 1, &region);
        vkEndCommandBuffer(cmd);
        VkSubmitInfo si {VK_STRUCTURE_TYPE_SUBMIT_INFO};
        si.commandBufferCount = 1;
        si.pCommandBuffers = &cmd;
        vkQueueSubmit(queue, 1, &si, VK_NULL_HANDLE);
        vkQueueWaitIdle(queue);
        void* mapped = nullptr;
        vkMapMemory(device, bmem, 0, static_cast<VkDeviceSize>(w) * h * 4, 0, &mapped);
        pixels.resize(static_cast<size_t>(w) * h * 4);
        if (mapped) std::memcpy(pixels.data(), mapped, pixels.size());
        vkUnmapMemory(device, bmem);
        vkFreeCommandBuffers(device, pool, 1, &cmd);
        vkDestroyBuffer(device, buf, nullptr);
        vkFreeMemory(device, bmem, nullptr);
        vkDestroyFramebuffer(device, fb, nullptr);
        vkDestroyImageView(device, view, nullptr);
        vkDestroyImage(device, image, nullptr);
        vkFreeMemory(device, mem, nullptr);
        return mapped != nullptr;
    }
};

Gpu g_gpu;

int prop_int(uint64_t obj, const char* key, int fallback) {
    if (!obj || !has_payload(obj)) return fallback;
    auto it = payload(obj).props.find(key);
    if (it == payload(obj).props.end() || it->second == 0) return fallback;
    return static_cast<int>(it->second);
}

void m_queue(Guest& g) {
    uint64_t q = make_object("MTLCommandQueue");
    payload(q).props["device"] = g.x[0];
    g.x[0] = q;
}
void m_cmdbuf(Guest& g) {
    uint64_t b = make_object("MTLCommandBuffer");
    payload(b).props["queue"] = g.x[0];
    g.x[0] = b;
}
void m_drawable(Guest& g) {
    uint64_t d = make_object("CAMetalDrawable");
    uint64_t tex = make_object("MTLTexture");
    int w = prop_int(g.x[0], "w", 1280);
    int h = prop_int(g.x[0], "h", 720);
    payload(tex).props["w"] = static_cast<uint64_t>(w);
    payload(tex).props["h"] = static_cast<uint64_t>(h);
    payload(d).props["texture"] = tex;
    payload(g.x[0]).props["drawable"] = d;
    g.x[0] = d;
}
void m_texture(Guest& g) { g.x[0] = payload(g.x[0]).props["texture"]; }
void m_set_drawable_size(Guest& g) {
    double w = 0, h = 0;
    std::memcpy(&w, g.v[0], 8);
    std::memcpy(&h, g.v[1], 8);
    if (w < 1 || h < 1) {
        if (g.x[2] > 0x10000) {
            std::memcpy(&w, reinterpret_cast<void*>(tbi(g.x[2])), 8);
            std::memcpy(&h, reinterpret_cast<void*>(tbi(g.x[2]) + 8), 8);
        }
    }
    if (w < 1) w = 1280;
    if (h < 1) h = 720;
    payload(g.x[0]).props["w"] = static_cast<uint64_t>(w);
    payload(g.x[0]).props["h"] = static_cast<uint64_t>(h);
}
void m_pass(Guest& g) { g.x[0] = make_object("MTLRenderPassDescriptor"); }
void m_color_atts(Guest& g) {
    uint64_t proxy = payload(g.x[0]).props["atts"];
    if (!proxy) {
        proxy = make_object("MTLRenderPassColorAttachmentDescriptorArray");
        payload(g.x[0]).props["atts"] = proxy;
    }
    g.x[0] = proxy;
}
void m_att(Guest& g) {
    uint64_t att = payload(g.x[0]).props["att0"];
    if (!att) {
        att = make_object("MTLRenderPassColorAttachmentDescriptor");
        payload(g.x[0]).props["att0"] = att;
    }
    g.x[0] = att;
}
void m_set_clear(Guest& g) {
    double d[4] {};
    if (g.x[2] > 0x10000) std::memcpy(d, reinterpret_cast<void*>(tbi(g.x[2])), sizeof(d));
    else {
        std::memcpy(&d[0], g.v[0], 8);
        std::memcpy(&d[1], g.v[1], 8);
        std::memcpy(&d[2], g.v[2], 8);
        std::memcpy(&d[3], g.v[3], 8);
    }
    payload(g.x[0]).bytes.resize(sizeof(d));
    std::memcpy(payload(g.x[0]).bytes.data(), d, sizeof(d));
}
void m_encoder(Guest& g) {
    uint64_t desc = g.x[2];
    uint64_t atts = desc ? payload(desc).props["atts"] : 0;
    uint64_t att = atts ? payload(atts).props["att0"] : 0;
    uint64_t tex = att ? payload(att).props["texture"] : 0;
    uint64_t enc = make_object("MTLRenderCommandEncoder");
    payload(enc).props["texture"] = tex;
    payload(enc).props["buffer"] = g.x[0];
    if (att && payload(att).bytes.size() >= 32) payload(enc).bytes = payload(att).bytes;
    payload(g.x[0]).props["encoder"] = enc;
    g.x[0] = enc;
}
void m_draw(Guest& g) {
    uint64_t buf = payload(g.x[0]).props["buffer"];
    if (buf) payload(buf).flag = true;
}
void m_present(Guest& g) {
    uint64_t drawable = g.x[2];
    payload(g.x[0]).props["drawable"] = drawable;
    if (drawable) payload(g.x[0]).props["texture"] = payload(drawable).props["texture"];
}
void m_wait(Guest& g) {
    uint64_t tex = payload(g.x[0]).props["texture"];
    uint64_t enc = payload(g.x[0]).props["encoder"];
    if (!tex && enc) tex = payload(enc).props["texture"];
    int w = prop_int(tex, "w", 64);
    int h = prop_int(tex, "h", 64);
    float c[4] = {0, 0, 0, 1};
    if (enc && payload(enc).bytes.size() >= 32) {
        double d[4] {};
        std::memcpy(d, payload(enc).bytes.data(), sizeof(d));
        for (int i = 0; i < 4; ++i) c[i] = static_cast<float>(d[i]);
    }
    std::vector<uint8_t> pixels;
    std::string err;
    bool triangle = payload(g.x[0]).flag;
    if (g_gpu.draw(w, h, c[0], c[1], c[2], c[3], triangle, pixels, err)) host_present(pixels.data(), w, h);
    else if (tracing()) std::fprintf(stderr, "metal present: %s\n", err.c_str());
}
void m_new_tex(Guest& g) {
    uint64_t desc = g.x[2];
    uint64_t tex = make_object("MTLTexture");
    int w = prop_int(desc, "width", 64);
    int h = prop_int(desc, "height", 64);
    payload(tex).props["w"] = static_cast<uint64_t>(w);
    payload(tex).props["h"] = static_cast<uint64_t>(h);
    g.x[0] = tex;
}
void m_tex_desc(Guest& g) { g.x[0] = make_object("MTLTextureDescriptor"); }
void m_pipe(Guest& g) { g.x[0] = make_object("MTLRenderPipelineState"); }
void m_buf(Guest& g) {
    uint64_t b = make_object("MTLBuffer");
    size_t n = g.x[3] ? g.x[3] : g.x[2];
    if (g.x[2] > 0x10000 && g.x[3] && g.x[3] < (32u << 20)) {
        payload(b).bytes.resize(g.x[3]);
        std::memcpy(payload(b).bytes.data(), reinterpret_cast<void*>(tbi(g.x[2])), g.x[3]);
        payload(b).props["ptr"] = g.x[2];
    } else if (n && n < (32u << 20)) {
        payload(b).bytes.resize(n);
        payload(b).props["ptr"] = reinterpret_cast<uint64_t>(payload(b).bytes.data());
    }
    g.x[0] = b;
}
void m_contents(Guest& g) {
    Payload& p = payload(g.x[0]);
    if (p.props["ptr"]) g.x[0] = p.props["ptr"];
    else if (!p.bytes.empty()) g.x[0] = reinterpret_cast<uint64_t>(p.bytes.data());
    else g.x[0] = 0;
}
void sh_device(Guest& g) {
    std::string err;
    g_gpu.init(err);
    g.x[0] = make_object("MTLDevice");
}
void sh_devices(Guest& g) {
    uint64_t d = make_object("MTLDevice");
    uint64_t a = make_object("NSArray");
    payload(a).kind = 2;
    payload(a).items.push_back(d);
    g.x[0] = a;
}
void m_release_enc(Guest&) {}
void m_dim_w(Guest& g) { g.x[0] = static_cast<uint64_t>(prop_int(g.x[0], "w", 0)); }
void m_dim_h(Guest& g) { g.x[0] = static_cast<uint64_t>(prop_int(g.x[0], "h", 0)); }
void m_set_texture(Guest& g) { payload(g.x[0]).props["texture"] = g.x[2]; }
void m_set_load(Guest& g) { payload(g.x[0]).props["load"] = g.x[2]; }
void m_set_device(Guest& g) { payload(g.x[0]).props["device"] = g.x[2]; }

}  // namespace

void metal_init() {
    ensure_class("MTLDevice", "NSObject", 64);
    ensure_class("MTLCommandQueue", "NSObject", 64);
    ensure_class("MTLCommandBuffer", "NSObject", 64);
    ensure_class("MTLRenderCommandEncoder", "NSObject", 64);
    ensure_class("MTLTexture", "NSObject", 64);
    ensure_class("MTLBuffer", "NSObject", 64);
    ensure_class("MTLRenderPassDescriptor", "NSObject", 64);
    ensure_class("MTLRenderPassColorAttachmentDescriptorArray", "NSObject", 64);
    ensure_class("MTLRenderPassColorAttachmentDescriptor", "NSObject", 64);
    ensure_class("MTLRenderPipelineState", "NSObject", 64);
    ensure_class("MTLTextureDescriptor", "NSObject", 64);
    ensure_class("CAMetalDrawable", "NSObject", 64);
    add_method("MTLDevice", "newCommandQueue", m_queue, false);
    add_method("MTLDevice", "newBufferWithBytes:length:options:", m_buf, false);
    add_method("MTLDevice", "newBufferWithLength:options:", m_buf, false);
    add_method("MTLDevice", "newTextureWithDescriptor:", m_new_tex, false);
    add_method("MTLDevice", "newRenderPipelineStateWithDescriptor:error:", m_pipe, false);
    add_method("MTLCommandQueue", "commandBuffer", m_cmdbuf, false);
    add_method("MTLCommandBuffer", "renderCommandEncoderWithDescriptor:", m_encoder, false);
    add_method("MTLCommandBuffer", "presentDrawable:", m_present, false);
    add_method("MTLCommandBuffer", "commit", m_wait, false);
    add_method("MTLCommandBuffer", "waitUntilCompleted", m_wait, false);
    add_method("MTLRenderCommandEncoder", "endEncoding", m_release_enc, false);
    add_method("MTLRenderCommandEncoder", "drawPrimitives:vertexStart:vertexCount:", m_draw, false);
    add_method("MTLRenderCommandEncoder", "setRenderPipelineState:", m_draw, false);
    add_method("MTLTexture", "width", m_dim_w, false);
    add_method("MTLTexture", "height", m_dim_h, false);
    add_method("MTLBuffer", "contents", m_contents, false);
    add_method("MTLRenderPassDescriptor", "renderPassDescriptor", m_pass, true);
    add_method("MTLRenderPassDescriptor", "colorAttachments", m_color_atts, false);
    add_method("MTLRenderPassColorAttachmentDescriptorArray", "objectAtIndexedSubscript:", m_att, false);
    add_method("MTLRenderPassColorAttachmentDescriptor", "setTexture:", m_set_texture, false);
    add_method("MTLRenderPassColorAttachmentDescriptor", "setClearColor:", m_set_clear, false);
    add_method("MTLRenderPassColorAttachmentDescriptor", "setLoadAction:", m_set_load, false);
    add_method("MTLTextureDescriptor", "texture2DDescriptorWithPixelFormat:width:height:mipmapped:", m_tex_desc, true);
    add_method("CAMetalLayer", "setDevice:", m_set_device, false);
    add_method("CAMetalLayer", "setDrawableSize:", m_set_drawable_size, false);
    add_method("CAMetalLayer", "nextDrawable", m_drawable, false);
    add_method("CAMetalDrawable", "texture", m_texture, false);
    register_shim("_MTLCreateSystemDefaultDevice", sh_device);
    register_shim("_MTLCopyAllDevices", sh_devices);
}

bool metal_selftest(std::string& err) {
    const char* icd = "/usr/share/vulkan/icd.d/lvp_icd.json";
    if (!std::getenv("VK_DRIVER_FILES") && !std::getenv("VK_ICD_FILENAMES")) {
        setenv("VK_DRIVER_FILES", icd, 0);
        setenv("VK_ICD_FILENAMES", icd, 0);
    }
    Gpu gpu;
    std::vector<uint8_t> pixels;
    if (!gpu.draw(64, 64, 0, 0, 1, 1, true, pixels, err)) return false;
    if (pixels.size() < 64 * 64 * 4) {
        err = "short readback";
        return false;
    }
    const uint8_t* center = pixels.data() + (32 * 64 + 32) * 4;
    const uint8_t* corner = pixels.data();
    if (center[0] < 180 || center[2] > 80) {
        err = "center pixel is not the red triangle";
        return false;
    }
    if (corner[2] < 180 || corner[0] > 80) {
        err = "corner pixel is not the blue clear";
        return false;
    }
    gpu.shutdown();
    return true;
}

}  // namespace lb
