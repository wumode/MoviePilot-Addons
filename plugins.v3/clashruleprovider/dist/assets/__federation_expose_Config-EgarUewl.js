import { importShared } from './__federation_fn_import-JrT3xvdd.js';
import { _ as _export_sfc, f as isValidUrl, w as validateIPs, u as useToast } from './_plugin-vue_export-helper-CyU6ZHU6.js';
import { V as VAceEditor } from './theme-monokai-CF_yROe-.js';

const {defineComponent:_defineComponent$7} = await importShared('vue');

const {unref:_unref$6,createTextVNode:_createTextVNode$7,resolveComponent:_resolveComponent$7,withCtx:_withCtx$7,createVNode:_createVNode$7,createElementVNode:_createElementVNode$7,withModifiers:_withModifiers$3,normalizeClass:_normalizeClass$1,openBlock:_openBlock$7,createElementBlock:_createElementBlock$4} = await importShared('vue');

const _hoisted_1$6 = { class: "mb-6" };
const _hoisted_2$4 = { class: "d-flex align-center gap-3" };
const _hoisted_3$2 = { class: "card-icon-avatar rounded-circle d-flex align-center justify-center" };
const _hoisted_4$2 = { class: "d-flex align-center gap-3" };
const _hoisted_5$2 = { class: "card-icon-avatar rounded-circle d-flex align-center justify-center" };
const _hoisted_6$2 = { class: "d-flex align-center gap-3" };
const _hoisted_7$2 = { class: "card-icon-avatar rounded-circle d-flex align-center justify-center" };
const _hoisted_8$2 = { class: "d-flex align-center gap-3" };
const _hoisted_9$2 = { class: "card-icon-avatar rounded-circle d-flex align-center justify-center" };
const {inject: inject$5} = await importShared('vue');

const _sfc_main$7 = /* @__PURE__ */ _defineComponent$7({
  __name: "MasterSwitches",
  setup(__props) {
    const config = inject$5("pluginConfig");
    return (_ctx, _cache) => {
      const _component_v_icon = _resolveComponent$7("v-icon");
      const _component_v_switch = _resolveComponent$7("v-switch");
      const _component_v_col = _resolveComponent$7("v-col");
      const _component_v_row = _resolveComponent$7("v-row");
      return _openBlock$7(), _createElementBlock$4("div", _hoisted_1$6, [
        _createVNode$7(_component_v_row, { dense: "" }, {
          default: _withCtx$7(() => [
            _createVNode$7(_component_v_col, {
              cols: "12",
              sm: "6",
              md: "3"
            }, {
              default: _withCtx$7(() => [
                _createElementVNode$7("div", {
                  class: _normalizeClass$1(["switch-card switch-card--primary rounded-lg pa-3 pa-md-4 d-flex align-center justify-space-between transition-all cursor-pointer select-none", { "switch-card--active": _unref$6(config).enabled }]),
                  onClick: _cache[2] || (_cache[2] = ($event) => _unref$6(config).enabled = !_unref$6(config).enabled)
                }, [
                  _createElementVNode$7("div", _hoisted_2$4, [
                    _createElementVNode$7("div", _hoisted_3$2, [
                      _createVNode$7(_component_v_icon, {
                        color: _unref$6(config).enabled ? "primary" : "grey-darken-1"
                      }, {
                        default: _withCtx$7(() => _cache[12] || (_cache[12] = [
                          _createTextVNode$7("mdi-power")
                        ])),
                        _: 1
                      }, 8, ["color"])
                    ]),
                    _cache[13] || (_cache[13] = _createElementVNode$7("div", null, [
                      _createElementVNode$7("div", { class: "font-weight-bold text-body-2" }, "启用插件"),
                      _createElementVNode$7("div", { class: "text-caption text-medium-emphasis" }, "运行插件服务")
                    ], -1))
                  ]),
                  _createVNode$7(_component_v_switch, {
                    modelValue: _unref$6(config).enabled,
                    "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => _unref$6(config).enabled = $event),
                    color: "primary",
                    "hide-details": "",
                    inset: "",
                    density: "compact",
                    onClick: _cache[1] || (_cache[1] = _withModifiers$3(() => {
                    }, ["stop"]))
                  }, null, 8, ["modelValue"])
                ], 2)
              ]),
              _: 1
            }),
            _createVNode$7(_component_v_col, {
              cols: "12",
              sm: "6",
              md: "3"
            }, {
              default: _withCtx$7(() => [
                _createElementVNode$7("div", {
                  class: _normalizeClass$1(["switch-card switch-card--info rounded-lg pa-3 pa-md-4 d-flex align-center justify-space-between transition-all cursor-pointer select-none", { "switch-card--active": _unref$6(config).proxy }]),
                  onClick: _cache[5] || (_cache[5] = ($event) => _unref$6(config).proxy = !_unref$6(config).proxy)
                }, [
                  _createElementVNode$7("div", _hoisted_4$2, [
                    _createElementVNode$7("div", _hoisted_5$2, [
                      _createVNode$7(_component_v_icon, {
                        color: _unref$6(config).proxy ? "info" : "grey-darken-1"
                      }, {
                        default: _withCtx$7(() => _cache[14] || (_cache[14] = [
                          _createTextVNode$7("mdi-lan-connect")
                        ])),
                        _: 1
                      }, 8, ["color"])
                    ]),
                    _cache[15] || (_cache[15] = _createElementVNode$7("div", null, [
                      _createElementVNode$7("div", { class: "font-weight-bold text-body-2" }, "启用代理"),
                      _createElementVNode$7("div", { class: "text-caption text-medium-emphasis" }, "网络请求代理")
                    ], -1))
                  ]),
                  _createVNode$7(_component_v_switch, {
                    modelValue: _unref$6(config).proxy,
                    "onUpdate:modelValue": _cache[3] || (_cache[3] = ($event) => _unref$6(config).proxy = $event),
                    color: "info",
                    "hide-details": "",
                    inset: "",
                    density: "compact",
                    onClick: _cache[4] || (_cache[4] = _withModifiers$3(() => {
                    }, ["stop"]))
                  }, null, 8, ["modelValue"])
                ], 2)
              ]),
              _: 1
            }),
            _createVNode$7(_component_v_col, {
              cols: "12",
              sm: "6",
              md: "3"
            }, {
              default: _withCtx$7(() => [
                _createElementVNode$7("div", {
                  class: _normalizeClass$1(["switch-card switch-card--warning rounded-lg pa-3 pa-md-4 d-flex align-center justify-space-between transition-all cursor-pointer select-none", { "switch-card--active": _unref$6(config).notify }]),
                  onClick: _cache[8] || (_cache[8] = ($event) => _unref$6(config).notify = !_unref$6(config).notify)
                }, [
                  _createElementVNode$7("div", _hoisted_6$2, [
                    _createElementVNode$7("div", _hoisted_7$2, [
                      _createVNode$7(_component_v_icon, {
                        color: _unref$6(config).notify ? "warning" : "grey-darken-1"
                      }, {
                        default: _withCtx$7(() => _cache[16] || (_cache[16] = [
                          _createTextVNode$7("mdi-bell-outline")
                        ])),
                        _: 1
                      }, 8, ["color"])
                    ]),
                    _cache[17] || (_cache[17] = _createElementVNode$7("div", null, [
                      _createElementVNode$7("div", { class: "font-weight-bold text-body-2" }, "运行通知"),
                      _createElementVNode$7("div", { class: "text-caption text-medium-emphasis" }, "发送消息推送")
                    ], -1))
                  ]),
                  _createVNode$7(_component_v_switch, {
                    modelValue: _unref$6(config).notify,
                    "onUpdate:modelValue": _cache[6] || (_cache[6] = ($event) => _unref$6(config).notify = $event),
                    color: "warning",
                    "hide-details": "",
                    inset: "",
                    density: "compact",
                    onClick: _cache[7] || (_cache[7] = _withModifiers$3(() => {
                    }, ["stop"]))
                  }, null, 8, ["modelValue"])
                ], 2)
              ]),
              _: 1
            }),
            _createVNode$7(_component_v_col, {
              cols: "12",
              sm: "6",
              md: "3"
            }, {
              default: _withCtx$7(() => [
                _createElementVNode$7("div", {
                  class: _normalizeClass$1(["switch-card switch-card--success rounded-lg pa-3 pa-md-4 d-flex align-center justify-space-between transition-all cursor-pointer select-none", { "switch-card--active": _unref$6(config).auto_update_subscriptions }]),
                  onClick: _cache[11] || (_cache[11] = ($event) => _unref$6(config).auto_update_subscriptions = !_unref$6(config).auto_update_subscriptions)
                }, [
                  _createElementVNode$7("div", _hoisted_8$2, [
                    _createElementVNode$7("div", _hoisted_9$2, [
                      _createVNode$7(_component_v_icon, {
                        color: _unref$6(config).auto_update_subscriptions ? "success" : "grey-darken-1"
                      }, {
                        default: _withCtx$7(() => _cache[18] || (_cache[18] = [
                          _createTextVNode$7(" mdi-sync ")
                        ])),
                        _: 1
                      }, 8, ["color"])
                    ]),
                    _cache[19] || (_cache[19] = _createElementVNode$7("div", null, [
                      _createElementVNode$7("div", { class: "font-weight-bold text-body-2" }, "自动更新"),
                      _createElementVNode$7("div", { class: "text-caption text-medium-emphasis" }, "定时同步订阅")
                    ], -1))
                  ]),
                  _createVNode$7(_component_v_switch, {
                    modelValue: _unref$6(config).auto_update_subscriptions,
                    "onUpdate:modelValue": _cache[9] || (_cache[9] = ($event) => _unref$6(config).auto_update_subscriptions = $event),
                    color: "success",
                    "hide-details": "",
                    inset: "",
                    density: "compact",
                    onClick: _cache[10] || (_cache[10] = _withModifiers$3(() => {
                    }, ["stop"]))
                  }, null, 8, ["modelValue"])
                ], 2)
              ]),
              _: 1
            })
          ]),
          _: 1
        })
      ]);
    };
  }
});

const MasterSwitches = /* @__PURE__ */ _export_sfc(_sfc_main$7, [["__scopeId", "data-v-f91316c4"]]);

const {defineComponent:_defineComponent$6} = await importShared('vue');

const {createTextVNode:_createTextVNode$6,resolveComponent:_resolveComponent$6,withCtx:_withCtx$6,createVNode:_createVNode$6,createElementVNode:_createElementVNode$6,unref:_unref$5,mergeProps:_mergeProps$2,toDisplayString:_toDisplayString$4,openBlock:_openBlock$6,createBlock:_createBlock$6} = await importShared('vue');

const _hoisted_1$5 = { class: "text-subtitle-2 font-weight-bold text-uppercase text-medium-emphasis mb-3 d-flex align-center" };
const {inject: inject$4} = await importShared('vue');
const _sfc_main$6 = /* @__PURE__ */ _defineComponent$6({
  __name: "BasicConfigSection",
  setup(__props) {
    const config = inject$4("pluginConfig");
    const dashboardComponents = ["Clash Info", "Traffic Stats"];
    const generateApiKey = () => {
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      let key = "";
      for (let i = 0; i < 32; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      config.apikey = key;
    };
    return (_ctx, _cache) => {
      const _component_v_icon = _resolveComponent$6("v-icon");
      const _component_v_text_field = _resolveComponent$6("v-text-field");
      const _component_v_col = _resolveComponent$6("v-col");
      const _component_v_btn = _resolveComponent$6("v-btn");
      const _component_v_tooltip = _resolveComponent$6("v-tooltip");
      const _component_v_chip = _resolveComponent$6("v-chip");
      const _component_v_select = _resolveComponent$6("v-select");
      const _component_v_row = _resolveComponent$6("v-row");
      const _component_v_card = _resolveComponent$6("v-card");
      return _openBlock$6(), _createBlock$6(_component_v_card, {
        variant: "flat",
        class: "section-card border rounded-lg pa-4 mb-6 bg-surface"
      }, {
        default: _withCtx$6(() => [
          _createElementVNode$6("div", _hoisted_1$5, [
            _createVNode$6(_component_v_icon, {
              size: "16",
              class: "mr-2",
              color: "primary"
            }, {
              default: _withCtx$6(() => _cache[3] || (_cache[3] = [
                _createTextVNode$6("mdi-server-network")
              ])),
              _: 1
            }),
            _cache[4] || (_cache[4] = _createTextVNode$6(" 基础配置 "))
          ]),
          _createVNode$6(_component_v_row, { dense: "" }, {
            default: _withCtx$6(() => [
              _createVNode$6(_component_v_col, {
                cols: "12",
                md: "4"
              }, {
                default: _withCtx$6(() => [
                  _createVNode$6(_component_v_text_field, {
                    modelValue: _unref$5(config).movie_pilot_url,
                    "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => _unref$5(config).movie_pilot_url = $event),
                    label: "MoviePilot URL",
                    variant: "outlined",
                    density: "comfortable",
                    placeholder: "http://localhost:3001",
                    hint: "MoviePilot 服务访问地址",
                    "persistent-hint": "",
                    class: "custom-input",
                    rules: [
                      (v) => !!v || "MoviePilot URL 不能为空",
                      (v) => _unref$5(isValidUrl)(v) || "请输入有效的 URL 地址"
                    ]
                  }, {
                    "prepend-inner": _withCtx$6(() => [
                      _createVNode$6(_component_v_icon, {
                        color: "primary",
                        size: "20"
                      }, {
                        default: _withCtx$6(() => _cache[5] || (_cache[5] = [
                          _createTextVNode$6("mdi-movie-open")
                        ])),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue", "rules"])
                ]),
                _: 1
              }),
              _createVNode$6(_component_v_col, {
                cols: "12",
                md: "4"
              }, {
                default: _withCtx$6(() => [
                  _createVNode$6(_component_v_text_field, {
                    modelValue: _unref$5(config).apikey,
                    "onUpdate:modelValue": _cache[1] || (_cache[1] = ($event) => _unref$5(config).apikey = $event),
                    label: "API Key",
                    variant: "outlined",
                    density: "comfortable",
                    placeholder: "留空使用系统 API Key",
                    hint: "服务鉴权凭证",
                    "persistent-hint": "",
                    class: "custom-input"
                  }, {
                    "prepend-inner": _withCtx$6(() => [
                      _createVNode$6(_component_v_icon, {
                        color: "warning",
                        size: "20"
                      }, {
                        default: _withCtx$6(() => _cache[6] || (_cache[6] = [
                          _createTextVNode$6("mdi-key-variant")
                        ])),
                        _: 1
                      })
                    ]),
                    "append-inner": _withCtx$6(() => [
                      _createVNode$6(_component_v_tooltip, {
                        location: "top",
                        text: "自动生成随机 Key"
                      }, {
                        activator: _withCtx$6(({ props: slotProps }) => [
                          _createVNode$6(_component_v_btn, _mergeProps$2(slotProps, {
                            icon: "mdi-autorenew",
                            size: "x-small",
                            variant: "text",
                            color: "primary",
                            class: "rotate-on-hover",
                            onClick: generateApiKey
                          }), null, 16)
                        ]),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue"])
                ]),
                _: 1
              }),
              _createVNode$6(_component_v_col, {
                cols: "12",
                md: "4"
              }, {
                default: _withCtx$6(() => [
                  _createVNode$6(_component_v_select, {
                    modelValue: _unref$5(config).dashboard_components,
                    "onUpdate:modelValue": _cache[2] || (_cache[2] = ($event) => _unref$5(config).dashboard_components = $event),
                    items: dashboardComponents,
                    label: "仪表盘组件",
                    variant: "outlined",
                    density: "comfortable",
                    multiple: "",
                    chips: "",
                    "closable-chips": "",
                    hint: "选中的组件将在仪表盘中展示",
                    "persistent-hint": "",
                    class: "custom-input"
                  }, {
                    "prepend-inner": _withCtx$6(() => [
                      _createVNode$6(_component_v_icon, {
                        color: "info",
                        size: "20"
                      }, {
                        default: _withCtx$6(() => _cache[7] || (_cache[7] = [
                          _createTextVNode$6("mdi-view-dashboard-outline")
                        ])),
                        _: 1
                      })
                    ]),
                    chip: _withCtx$6(({ props: slotProps, item }) => [
                      _createVNode$6(_component_v_chip, _mergeProps$2(slotProps, {
                        size: "small",
                        color: "info",
                        variant: "tonal",
                        class: "font-weight-medium"
                      }), {
                        default: _withCtx$6(() => [
                          _createTextVNode$6(_toDisplayString$4(item.value), 1)
                        ]),
                        _: 2
                      }, 1040)
                    ]),
                    _: 1
                  }, 8, ["modelValue"])
                ]),
                _: 1
              })
            ]),
            _: 1
          })
        ]),
        _: 1
      });
    };
  }
});

const BasicConfigSection = /* @__PURE__ */ _export_sfc(_sfc_main$6, [["__scopeId", "data-v-204cdd08"]]);

const {defineComponent:_defineComponent$5} = await importShared('vue');

const {createElementVNode:_createElementVNode$5,createTextVNode:_createTextVNode$5,resolveComponent:_resolveComponent$5,withCtx:_withCtx$5,createVNode:_createVNode$5,unref:_unref$4,withModifiers:_withModifiers$2,toDisplayString:_toDisplayString$3,mergeProps:_mergeProps$1,openBlock:_openBlock$5,createElementBlock:_createElementBlock$3,createCommentVNode:_createCommentVNode$1,renderList:_renderList$2,Fragment:_Fragment$2,createBlock:_createBlock$5} = await importShared('vue');

const _hoisted_1$4 = { class: "mb-4" };
const _hoisted_2$3 = { class: "d-flex align-center gap-2" };
const _hoisted_3$1 = { class: "d-flex align-center gap-2" };
const _hoisted_4$1 = { class: "d-flex align-center justify-space-between mb-4" };
const _hoisted_5$1 = { class: "text-subtitle-1 font-weight-bold d-flex align-center" };
const _hoisted_6$1 = { class: "d-flex align-center gap-2" };
const _hoisted_7$1 = {
  key: 0,
  class: "empty-box rounded-lg pa-8 text-center border-dashed"
};
const _hoisted_8$1 = { class: "d-flex align-center gap-3 w-100" };
const _hoisted_9$1 = {
  class: "text-subtitle-2 font-weight-bold text-truncate",
  style: { "max-width": "320px" }
};
const _hoisted_10$1 = ["onClick"];
const _hoisted_11$1 = ["onClick"];
const _hoisted_12$1 = ["onClick"];
const _hoisted_13 = ["onClick"];
const {inject: inject$3} = await importShared('vue');
const _sfc_main$5 = /* @__PURE__ */ _defineComponent$5({
  __name: "SubscriptionConfigTab",
  emits: ["open-template"],
  setup(__props, { emit: __emit }) {
    const config = inject$3("pluginConfig");
    const emit = __emit;
    const activeOptionsCount = (item) => {
      let count = 0;
      if (item.rules) count++;
      if (item["rule-providers"]) count++;
      if (item["proxy-groups"]) count++;
      if (item["proxy-providers"]) count++;
      return count;
    };
    const getUrlHostname = (urlStr) => {
      if (!urlStr) return "未配置订阅 URL";
      try {
        const parsed = new URL(urlStr);
        return parsed.hostname;
      } catch {
        return urlStr.length > 30 ? urlStr.substring(0, 30) + "..." : urlStr;
      }
    };
    const addSubscriptionConfig = () => {
      config.subscriptions_config.push({
        url: "",
        rules: false,
        proxies: true,
        "proxy-groups": false,
        "rule-providers": false,
        "proxy-providers": false,
        user_agent: null
      });
    };
    const removeSubscriptionConfig = (index) => {
      config.subscriptions_config.splice(index, 1);
    };
    return (_ctx, _cache) => {
      const _component_v_icon = _resolveComponent$5("v-icon");
      const _component_v_switch = _resolveComponent$5("v-switch");
      const _component_v_col = _resolveComponent$5("v-col");
      const _component_v_row = _resolveComponent$5("v-row");
      const _component_v_chip = _resolveComponent$5("v-chip");
      const _component_v_combobox = _resolveComponent$5("v-combobox");
      const _component_v_divider = _resolveComponent$5("v-divider");
      const _component_v_btn = _resolveComponent$5("v-btn");
      const _component_v_spacer = _resolveComponent$5("v-spacer");
      const _component_v_expansion_panel_title = _resolveComponent$5("v-expansion-panel-title");
      const _component_v_text_field = _resolveComponent$5("v-text-field");
      const _component_v_expansion_panel_text = _resolveComponent$5("v-expansion-panel-text");
      const _component_v_expansion_panel = _resolveComponent$5("v-expansion-panel");
      const _component_v_expansion_panels = _resolveComponent$5("v-expansion-panels");
      const _component_v_card = _resolveComponent$5("v-card");
      return _openBlock$5(), _createBlock$5(_component_v_card, {
        variant: "flat",
        class: "pa-4 border rounded-lg bg-surface"
      }, {
        default: _withCtx$5(() => [
          _createElementVNode$5("div", _hoisted_1$4, [
            _cache[16] || (_cache[16] = _createElementVNode$5("div", { class: "text-subtitle-2 font-weight-bold mb-2" }, "节点分组与过滤设置", -1)),
            _createVNode$5(_component_v_row, { dense: "" }, {
              default: _withCtx$5(() => [
                _createVNode$5(_component_v_col, {
                  cols: "12",
                  md: "6"
                }, {
                  default: _withCtx$5(() => [
                    _createElementVNode$5("div", {
                      class: "feature-toggle-item d-flex align-center justify-space-between border rounded-lg pa-3 cursor-pointer select-none transition-all",
                      onClick: _cache[2] || (_cache[2] = ($event) => _unref$4(config).group_by_country = !_unref$4(config).group_by_country)
                    }, [
                      _createElementVNode$5("div", _hoisted_2$3, [
                        _createVNode$5(_component_v_icon, {
                          color: "primary",
                          size: "20"
                        }, {
                          default: _withCtx$5(() => _cache[12] || (_cache[12] = [
                            _createTextVNode$5("mdi-flag-outline")
                          ])),
                          _: 1
                        }),
                        _cache[13] || (_cache[13] = _createElementVNode$5("div", null, [
                          _createElementVNode$5("div", { class: "text-body-2 font-weight-medium" }, "按国家/地区分组节点"),
                          _createElementVNode$5("div", { class: "text-caption text-medium-emphasis" }, "根据节点名称自动归类国家代理组")
                        ], -1))
                      ]),
                      _createVNode$5(_component_v_switch, {
                        modelValue: _unref$4(config).group_by_country,
                        "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => _unref$4(config).group_by_country = $event),
                        color: "primary",
                        "hide-details": "",
                        inset: "",
                        density: "compact",
                        onClick: _cache[1] || (_cache[1] = _withModifiers$2(() => {
                        }, ["stop"]))
                      }, null, 8, ["modelValue"])
                    ])
                  ]),
                  _: 1
                }),
                _createVNode$5(_component_v_col, {
                  cols: "12",
                  md: "6"
                }, {
                  default: _withCtx$5(() => [
                    _createElementVNode$5("div", {
                      class: "feature-toggle-item d-flex align-center justify-space-between border rounded-lg pa-3 cursor-pointer select-none transition-all",
                      onClick: _cache[5] || (_cache[5] = ($event) => _unref$4(config).group_by_region = !_unref$4(config).group_by_region)
                    }, [
                      _createElementVNode$5("div", _hoisted_3$1, [
                        _createVNode$5(_component_v_icon, {
                          color: "primary",
                          size: "20"
                        }, {
                          default: _withCtx$5(() => _cache[14] || (_cache[14] = [
                            _createTextVNode$5("mdi-earth")
                          ])),
                          _: 1
                        }),
                        _cache[15] || (_cache[15] = _createElementVNode$5("div", null, [
                          _createElementVNode$5("div", { class: "text-body-2 font-weight-medium" }, "按大洲/区域分组节点"),
                          _createElementVNode$5("div", { class: "text-caption text-medium-emphasis" }, "根据节点名称自动归类大洲代理组")
                        ], -1))
                      ]),
                      _createVNode$5(_component_v_switch, {
                        modelValue: _unref$4(config).group_by_region,
                        "onUpdate:modelValue": _cache[3] || (_cache[3] = ($event) => _unref$4(config).group_by_region = $event),
                        color: "primary",
                        "hide-details": "",
                        inset: "",
                        density: "compact",
                        onClick: _cache[4] || (_cache[4] = _withModifiers$2(() => {
                        }, ["stop"]))
                      }, null, 8, ["modelValue"])
                    ])
                  ]),
                  _: 1
                })
              ]),
              _: 1
            })
          ]),
          _createVNode$5(_component_v_combobox, {
            modelValue: _unref$4(config).filter_keywords,
            "onUpdate:modelValue": _cache[6] || (_cache[6] = ($event) => _unref$4(config).filter_keywords = $event),
            label: "节点过滤关键词",
            variant: "outlined",
            density: "comfortable",
            multiple: "",
            chips: "",
            "closable-chips": "",
            clearable: "",
            hint: "按 Enter 添加无需导入的节点过滤关键字",
            "persistent-hint": "",
            class: "mb-6"
          }, {
            "prepend-inner": _withCtx$5(() => [
              _createVNode$5(_component_v_icon, {
                color: "info",
                size: "20"
              }, {
                default: _withCtx$5(() => _cache[17] || (_cache[17] = [
                  _createTextVNode$5("mdi-filter-variant")
                ])),
                _: 1
              })
            ]),
            chip: _withCtx$5(({ props: slotProps, item }) => [
              _createVNode$5(_component_v_chip, _mergeProps$1(slotProps, {
                closable: "",
                size: "small",
                color: "info",
                variant: "tonal",
                class: "font-weight-medium"
              }), {
                default: _withCtx$5(() => [
                  _createTextVNode$5(_toDisplayString$3(item.value), 1)
                ]),
                _: 2
              }, 1040)
            ]),
            _: 1
          }, 8, ["modelValue"]),
          _createVNode$5(_component_v_divider, { class: "my-4" }),
          _createElementVNode$5("div", _hoisted_4$1, [
            _createElementVNode$5("div", _hoisted_5$1, [
              _createVNode$5(_component_v_icon, {
                color: "primary",
                class: "mr-2"
              }, {
                default: _withCtx$5(() => _cache[18] || (_cache[18] = [
                  _createTextVNode$5("mdi-link-box-variant-outline")
                ])),
                _: 1
              }),
              _cache[19] || (_cache[19] = _createTextVNode$5(" 订阅链接配置列表 "))
            ]),
            _createElementVNode$5("div", _hoisted_6$1, [
              _createVNode$5(_component_v_btn, {
                size: "small",
                color: "primary",
                variant: "tonal",
                class: "rounded-lg",
                onClick: addSubscriptionConfig
              }, {
                default: _withCtx$5(() => [
                  _createVNode$5(_component_v_icon, { start: "" }, {
                    default: _withCtx$5(() => _cache[20] || (_cache[20] = [
                      _createTextVNode$5("mdi-plus")
                    ])),
                    _: 1
                  }),
                  _cache[21] || (_cache[21] = _createTextVNode$5(" 添加订阅 "))
                ]),
                _: 1
              }),
              _createVNode$5(_component_v_btn, {
                size: "small",
                color: "secondary",
                variant: "outlined",
                class: "rounded-lg",
                onClick: _cache[7] || (_cache[7] = ($event) => emit("open-template"))
              }, {
                default: _withCtx$5(() => [
                  _createVNode$5(_component_v_icon, { start: "" }, {
                    default: _withCtx$5(() => _cache[22] || (_cache[22] = [
                      _createTextVNode$5("mdi-file-code-outline")
                    ])),
                    _: 1
                  }),
                  _cache[23] || (_cache[23] = _createTextVNode$5(" 配置模板 "))
                ]),
                _: 1
              })
            ])
          ]),
          !_unref$4(config).subscriptions_config || _unref$4(config).subscriptions_config.length === 0 ? (_openBlock$5(), _createElementBlock$3("div", _hoisted_7$1, [
            _createVNode$5(_component_v_icon, {
              size: "48",
              color: "grey-lighten-1",
              class: "mb-2"
            }, {
              default: _withCtx$5(() => _cache[24] || (_cache[24] = [
                _createTextVNode$5("mdi-link-off")
              ])),
              _: 1
            }),
            _cache[27] || (_cache[27] = _createElementVNode$5("div", { class: "text-body-1 font-weight-medium text-medium-emphasis" }, "暂未配置任何订阅链接", -1)),
            _cache[28] || (_cache[28] = _createElementVNode$5("div", { class: "text-caption text-disabled mb-4" }, "点击上方“添加订阅”按钮以配置 Clash 规则订阅", -1)),
            _createVNode$5(_component_v_btn, {
              size: "small",
              color: "primary",
              variant: "flat",
              onClick: addSubscriptionConfig
            }, {
              default: _withCtx$5(() => [
                _createVNode$5(_component_v_icon, { start: "" }, {
                  default: _withCtx$5(() => _cache[25] || (_cache[25] = [
                    _createTextVNode$5("mdi-plus")
                  ])),
                  _: 1
                }),
                _cache[26] || (_cache[26] = _createTextVNode$5(" 立即添加 "))
              ]),
              _: 1
            })
          ])) : (_openBlock$5(), _createBlock$5(_component_v_expansion_panels, {
            key: 1,
            multiple: "",
            class: "sub-panels"
          }, {
            default: _withCtx$5(() => [
              (_openBlock$5(true), _createElementBlock$3(_Fragment$2, null, _renderList$2(_unref$4(config).subscriptions_config, (item, index) => {
                return _openBlock$5(), _createBlock$5(_component_v_expansion_panel, {
                  key: index,
                  class: "border rounded-lg mb-3 overflow-hidden",
                  elevation: "0"
                }, {
                  default: _withCtx$5(() => [
                    _createVNode$5(_component_v_expansion_panel_title, { class: "py-3 px-4" }, {
                      default: _withCtx$5(() => [
                        _createElementVNode$5("div", _hoisted_8$1, [
                          _createVNode$5(_component_v_chip, {
                            color: "primary",
                            size: "small",
                            variant: "tonal",
                            class: "font-weight-bold"
                          }, {
                            default: _withCtx$5(() => [
                              _createTextVNode$5(" #" + _toDisplayString$3(index + 1), 1)
                            ]),
                            _: 2
                          }, 1024),
                          _createElementVNode$5("div", _hoisted_9$1, _toDisplayString$3(getUrlHostname(item.url)), 1),
                          item.user_agent ? (_openBlock$5(), _createBlock$5(_component_v_chip, {
                            key: 0,
                            size: "x-small",
                            color: "info",
                            variant: "tonal",
                            class: "ml-2"
                          }, {
                            default: _withCtx$5(() => [
                              _createTextVNode$5(" UA: " + _toDisplayString$3(item.user_agent), 1)
                            ]),
                            _: 2
                          }, 1024)) : _createCommentVNode$1("", true),
                          activeOptionsCount(item) > 0 ? (_openBlock$5(), _createBlock$5(_component_v_chip, {
                            key: 1,
                            size: "x-small",
                            color: "success",
                            variant: "tonal",
                            class: "ml-2"
                          }, {
                            default: _withCtx$5(() => [
                              _createTextVNode$5(" 已勾选 " + _toDisplayString$3(activeOptionsCount(item)) + " 项保留 ", 1)
                            ]),
                            _: 2
                          }, 1024)) : _createCommentVNode$1("", true),
                          _createVNode$5(_component_v_spacer),
                          _createVNode$5(_component_v_btn, {
                            icon: "mdi-delete-outline",
                            size: "small",
                            color: "error",
                            variant: "text",
                            class: "mr-2",
                            onClick: _withModifiers$2(($event) => removeSubscriptionConfig(index), ["stop"])
                          }, null, 8, ["onClick"])
                        ])
                      ]),
                      _: 2
                    }, 1024),
                    _createVNode$5(_component_v_expansion_panel_text, { class: "pa-4" }, {
                      default: _withCtx$5(() => [
                        _createVNode$5(_component_v_text_field, {
                          modelValue: item.url,
                          "onUpdate:modelValue": ($event) => item.url = $event,
                          label: "订阅 URL 链接",
                          variant: "outlined",
                          density: "comfortable",
                          placeholder: "https://example.com/clash/config.yaml",
                          class: "mb-4",
                          rules: [
                            (v) => !!v || "订阅链接不能为空",
                            (v) => _unref$4(isValidUrl)(v) || "请输入有效的 URL 地址"
                          ]
                        }, {
                          "prepend-inner": _withCtx$5(() => [
                            _createVNode$5(_component_v_icon, {
                              color: "primary",
                              size: "20"
                            }, {
                              default: _withCtx$5(() => _cache[29] || (_cache[29] = [
                                _createTextVNode$5("mdi-link")
                              ])),
                              _: 1
                            })
                          ]),
                          _: 2
                        }, 1032, ["modelValue", "onUpdate:modelValue", "rules"]),
                        _createVNode$5(_component_v_text_field, {
                          modelValue: item.user_agent,
                          "onUpdate:modelValue": ($event) => item.user_agent = $event,
                          label: "User-Agent (可选)",
                          variant: "outlined",
                          density: "comfortable",
                          placeholder: "例如: ClashMeta / ClashforWindows / Mozilla/5.0...",
                          hint: "自定义请求订阅链接时使用的 User-Agent",
                          "persistent-hint": "",
                          clearable: "",
                          class: "mb-4"
                        }, {
                          "prepend-inner": _withCtx$5(() => [
                            _createVNode$5(_component_v_icon, {
                              color: "primary",
                              size: "20"
                            }, {
                              default: _withCtx$5(() => _cache[30] || (_cache[30] = [
                                _createTextVNode$5("mdi-incognito")
                              ])),
                              _: 1
                            })
                          ]),
                          _: 2
                        }, 1032, ["modelValue", "onUpdate:modelValue"]),
                        _cache[35] || (_cache[35] = _createElementVNode$5("div", { class: "text-caption text-medium-emphasis font-weight-bold mb-2" }, "保留选项设置", -1)),
                        _createVNode$5(_component_v_row, { dense: "" }, {
                          default: _withCtx$5(() => [
                            _createVNode$5(_component_v_col, {
                              cols: "12",
                              sm: "6",
                              md: "3"
                            }, {
                              default: _withCtx$5(() => [
                                _createElementVNode$5("div", {
                                  class: "option-toggle-box rounded-lg pa-2 border d-flex align-center justify-space-between cursor-pointer select-none",
                                  onClick: ($event) => item.rules = !item.rules
                                }, [
                                  _cache[31] || (_cache[31] = _createElementVNode$5("span", { class: "text-caption font-weight-medium" }, "保留规则", -1)),
                                  _createVNode$5(_component_v_switch, {
                                    modelValue: item.rules,
                                    "onUpdate:modelValue": ($event) => item.rules = $event,
                                    color: "primary",
                                    "hide-details": "",
                                    density: "compact",
                                    onClick: _cache[8] || (_cache[8] = _withModifiers$2(() => {
                                    }, ["stop"]))
                                  }, null, 8, ["modelValue", "onUpdate:modelValue"])
                                ], 8, _hoisted_10$1)
                              ]),
                              _: 2
                            }, 1024),
                            _createVNode$5(_component_v_col, {
                              cols: "12",
                              sm: "6",
                              md: "3"
                            }, {
                              default: _withCtx$5(() => [
                                _createElementVNode$5("div", {
                                  class: "option-toggle-box rounded-lg pa-2 border d-flex align-center justify-space-between cursor-pointer select-none",
                                  onClick: ($event) => item["rule-providers"] = !item["rule-providers"]
                                }, [
                                  _cache[32] || (_cache[32] = _createElementVNode$5("span", { class: "text-caption font-weight-medium" }, "保留规则集合", -1)),
                                  _createVNode$5(_component_v_switch, {
                                    modelValue: item["rule-providers"],
                                    "onUpdate:modelValue": ($event) => item["rule-providers"] = $event,
                                    color: "primary",
                                    "hide-details": "",
                                    density: "compact",
                                    onClick: _cache[9] || (_cache[9] = _withModifiers$2(() => {
                                    }, ["stop"]))
                                  }, null, 8, ["modelValue", "onUpdate:modelValue"])
                                ], 8, _hoisted_11$1)
                              ]),
                              _: 2
                            }, 1024),
                            _createVNode$5(_component_v_col, {
                              cols: "12",
                              sm: "6",
                              md: "3"
                            }, {
                              default: _withCtx$5(() => [
                                _createElementVNode$5("div", {
                                  class: "option-toggle-box rounded-lg pa-2 border d-flex align-center justify-space-between cursor-pointer select-none",
                                  onClick: ($event) => item["proxy-groups"] = !item["proxy-groups"]
                                }, [
                                  _cache[33] || (_cache[33] = _createElementVNode$5("span", { class: "text-caption font-weight-medium" }, "保留代理组", -1)),
                                  _createVNode$5(_component_v_switch, {
                                    modelValue: item["proxy-groups"],
                                    "onUpdate:modelValue": ($event) => item["proxy-groups"] = $event,
                                    color: "primary",
                                    "hide-details": "",
                                    density: "compact",
                                    onClick: _cache[10] || (_cache[10] = _withModifiers$2(() => {
                                    }, ["stop"]))
                                  }, null, 8, ["modelValue", "onUpdate:modelValue"])
                                ], 8, _hoisted_12$1)
                              ]),
                              _: 2
                            }, 1024),
                            _createVNode$5(_component_v_col, {
                              cols: "12",
                              sm: "6",
                              md: "3"
                            }, {
                              default: _withCtx$5(() => [
                                _createElementVNode$5("div", {
                                  class: "option-toggle-box rounded-lg pa-2 border d-flex align-center justify-space-between cursor-pointer select-none",
                                  onClick: ($event) => item["proxy-providers"] = !item["proxy-providers"]
                                }, [
                                  _cache[34] || (_cache[34] = _createElementVNode$5("span", { class: "text-caption font-weight-medium" }, "保留代理集合", -1)),
                                  _createVNode$5(_component_v_switch, {
                                    modelValue: item["proxy-providers"],
                                    "onUpdate:modelValue": ($event) => item["proxy-providers"] = $event,
                                    color: "primary",
                                    "hide-details": "",
                                    density: "compact",
                                    onClick: _cache[11] || (_cache[11] = _withModifiers$2(() => {
                                    }, ["stop"]))
                                  }, null, 8, ["modelValue", "onUpdate:modelValue"])
                                ], 8, _hoisted_13)
                              ]),
                              _: 2
                            }, 1024)
                          ]),
                          _: 2
                        }, 1024)
                      ]),
                      _: 2
                    }, 1024)
                  ]),
                  _: 2
                }, 1024);
              }), 128))
            ]),
            _: 1
          }))
        ]),
        _: 1
      });
    };
  }
});

const SubscriptionConfigTab = /* @__PURE__ */ _export_sfc(_sfc_main$5, [["__scopeId", "data-v-4904dc24"]]);

const {defineComponent:_defineComponent$4} = await importShared('vue');

const {createElementVNode:_createElementVNode$4,resolveComponent:_resolveComponent$4,withCtx:_withCtx$4,createVNode:_createVNode$4,unref:_unref$3,renderList:_renderList$1,Fragment:_Fragment$1,openBlock:_openBlock$4,createElementBlock:_createElementBlock$2,createTextVNode:_createTextVNode$4,normalizeClass:_normalizeClass,createBlock:_createBlock$4} = await importShared('vue');

const {ref: ref$2,inject: inject$2} = await importShared('vue');
const _sfc_main$4 = /* @__PURE__ */ _defineComponent$4({
  __name: "ClashApiConfigTab",
  setup(__props) {
    const config = inject$2("pluginConfig");
    const showSecrets = ref$2({ 0: false });
    const toggleSecret = (index) => {
      showSecrets.value[index] = !showSecrets.value[index];
    };
    const addClashConfig = () => {
      const newIndex = config.clash_dashboards.length;
      config.clash_dashboards.push({ url: "", secret: "" });
      showSecrets.value[newIndex] = false;
    };
    const removeClashConfig = (index) => {
      config.clash_dashboards.splice(index, 1);
      delete showSecrets.value[index];
      if (config.active_dashboard === index) {
        config.active_dashboard = config.clash_dashboards.length > 0 ? 0 : null;
      }
    };
    return (_ctx, _cache) => {
      const _component_v_alert = _resolveComponent$4("v-alert");
      const _component_v_radio = _resolveComponent$4("v-radio");
      const _component_v_col = _resolveComponent$4("v-col");
      const _component_v_icon = _resolveComponent$4("v-icon");
      const _component_v_text_field = _resolveComponent$4("v-text-field");
      const _component_v_btn = _resolveComponent$4("v-btn");
      const _component_v_row = _resolveComponent$4("v-row");
      const _component_v_radio_group = _resolveComponent$4("v-radio-group");
      const _component_v_card = _resolveComponent$4("v-card");
      return _openBlock$4(), _createBlock$4(_component_v_card, {
        variant: "flat",
        class: "pa-4 border rounded-lg bg-surface"
      }, {
        default: _withCtx$4(() => [
          _createVNode$4(_component_v_alert, {
            type: "info",
            variant: "tonal",
            density: "comfortable",
            class: "mb-4 rounded-lg",
            icon: "mdi-information-outline"
          }, {
            default: _withCtx$4(() => _cache[1] || (_cache[1] = [
              _createElementVNode$4("div", { class: "text-caption font-weight-medium" }, " Clash API 用于通知 Clash 更新规则集；选中的活动面板将作为小组件展示。 ", -1)
            ])),
            _: 1
          }),
          _createVNode$4(_component_v_radio_group, {
            modelValue: _unref$3(config).active_dashboard,
            "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => _unref$3(config).active_dashboard = $event),
            "hide-details": "",
            class: "w-100"
          }, {
            default: _withCtx$4(() => [
              (_openBlock$4(true), _createElementBlock$2(_Fragment$1, null, _renderList$1(_unref$3(config).clash_dashboards, (item, index) => {
                return _openBlock$4(), _createElementBlock$2("div", {
                  key: index,
                  class: _normalizeClass(["api-endpoint-card border rounded-lg pa-3 pa-md-4 mb-3 transition-all", { "api-endpoint-card--active": _unref$3(config).active_dashboard === index }])
                }, [
                  _createVNode$4(_component_v_row, {
                    dense: "",
                    align: "center"
                  }, {
                    default: _withCtx$4(() => [
                      _createVNode$4(_component_v_col, {
                        cols: "12",
                        sm: "1",
                        class: "d-flex align-center justify-start justify-sm-center"
                      }, {
                        default: _withCtx$4(() => [
                          _createVNode$4(_component_v_radio, {
                            value: index,
                            color: "primary",
                            "hide-details": ""
                          }, null, 8, ["value"]),
                          _cache[2] || (_cache[2] = _createElementVNode$4("span", { class: "text-caption font-weight-bold ml-1 d-sm-none" }, "设为活动面板", -1))
                        ]),
                        _: 2
                      }, 1024),
                      _createVNode$4(_component_v_col, {
                        cols: "12",
                        sm: "5"
                      }, {
                        default: _withCtx$4(() => [
                          _createVNode$4(_component_v_text_field, {
                            modelValue: item.url,
                            "onUpdate:modelValue": ($event) => item.url = $event,
                            label: "API 访问 URL",
                            variant: "outlined",
                            density: "comfortable",
                            placeholder: "http://localhost:9090",
                            "hide-details": "auto",
                            rules: [(v) => !v || _unref$3(isValidUrl)(v) || "请输入有效的 URL"]
                          }, {
                            "prepend-inner": _withCtx$4(() => [
                              _createVNode$4(_component_v_icon, {
                                color: "primary",
                                size: "20"
                              }, {
                                default: _withCtx$4(() => _cache[3] || (_cache[3] = [
                                  _createTextVNode$4("mdi-web")
                                ])),
                                _: 1
                              })
                            ]),
                            _: 2
                          }, 1032, ["modelValue", "onUpdate:modelValue", "rules"])
                        ]),
                        _: 2
                      }, 1024),
                      _createVNode$4(_component_v_col, {
                        cols: "12",
                        sm: "5"
                      }, {
                        default: _withCtx$4(() => [
                          _createVNode$4(_component_v_text_field, {
                            modelValue: item.secret,
                            "onUpdate:modelValue": ($event) => item.secret = $event,
                            label: "API 密钥 (Secret)",
                            variant: "outlined",
                            density: "comfortable",
                            placeholder: "your-clash-secret",
                            "hide-details": "auto",
                            type: showSecrets.value[index] ? "text" : "password",
                            "append-inner-icon": showSecrets.value[index] ? "mdi-eye-off-outline" : "mdi-eye-outline",
                            "onClick:appendInner": ($event) => toggleSecret(index)
                          }, {
                            "prepend-inner": _withCtx$4(() => [
                              _createVNode$4(_component_v_icon, {
                                color: "warning",
                                size: "20"
                              }, {
                                default: _withCtx$4(() => _cache[4] || (_cache[4] = [
                                  _createTextVNode$4("mdi-shield-key-outline")
                                ])),
                                _: 1
                              })
                            ]),
                            _: 2
                          }, 1032, ["modelValue", "onUpdate:modelValue", "type", "append-inner-icon", "onClick:appendInner"])
                        ]),
                        _: 2
                      }, 1024),
                      _createVNode$4(_component_v_col, {
                        cols: "12",
                        sm: "1",
                        class: "d-flex align-center justify-end"
                      }, {
                        default: _withCtx$4(() => [
                          _createVNode$4(_component_v_btn, {
                            icon: "mdi-delete-outline",
                            color: "error",
                            variant: "text",
                            size: "small",
                            onClick: ($event) => removeClashConfig(index)
                          }, null, 8, ["onClick"])
                        ]),
                        _: 2
                      }, 1024)
                    ]),
                    _: 2
                  }, 1024)
                ], 2);
              }), 128))
            ]),
            _: 1
          }, 8, ["modelValue"]),
          _createVNode$4(_component_v_btn, {
            size: "small",
            color: "primary",
            variant: "tonal",
            class: "rounded-lg mt-2",
            onClick: addClashConfig
          }, {
            default: _withCtx$4(() => [
              _createVNode$4(_component_v_icon, { start: "" }, {
                default: _withCtx$4(() => _cache[5] || (_cache[5] = [
                  _createTextVNode$4("mdi-plus")
                ])),
                _: 1
              }),
              _cache[6] || (_cache[6] = _createTextVNode$4(" 添加 Clash API 地址 "))
            ]),
            _: 1
          })
        ]),
        _: 1
      });
    };
  }
});

const ClashApiConfigTab = /* @__PURE__ */ _export_sfc(_sfc_main$4, [["__scopeId", "data-v-ee984b40"]]);

const {defineComponent:_defineComponent$3} = await importShared('vue');

const {unref:_unref$2,createTextVNode:_createTextVNode$3,resolveComponent:_resolveComponent$3,withCtx:_withCtx$3,createVNode:_createVNode$3,createElementVNode:_createElementVNode$3,renderList:_renderList,Fragment:_Fragment,openBlock:_openBlock$3,createElementBlock:_createElementBlock$1,toDisplayString:_toDisplayString$2,createBlock:_createBlock$3} = await importShared('vue');

const _hoisted_1$3 = { class: "d-flex align-center gap-1 flex-wrap mb-4" };
const {inject: inject$1} = await importShared('vue');

const _sfc_main$3 = /* @__PURE__ */ _defineComponent$3({
  __name: "ExecutionConfigTab",
  setup(__props) {
    const config = inject$1("pluginConfig");
    const cronPresets = [
      { label: "每 6 小时", value: "0 */6 * * *" },
      { label: "每 12 小时", value: "0 */12 * * *" },
      { label: "每日 04:00", value: "0 4 * * *" },
      { label: "每日零点", value: "0 0 * * *" }
    ];
    return (_ctx, _cache) => {
      const _component_v_icon = _resolveComponent$3("v-icon");
      const _component_v_text_field = _resolveComponent$3("v-text-field");
      const _component_v_chip = _resolveComponent$3("v-chip");
      const _component_v_col = _resolveComponent$3("v-col");
      const _component_v_row = _resolveComponent$3("v-row");
      const _component_v_card = _resolveComponent$3("v-card");
      return _openBlock$3(), _createBlock$3(_component_v_card, {
        variant: "flat",
        class: "pa-4 border rounded-lg bg-surface"
      }, {
        default: _withCtx$3(() => [
          _createVNode$3(_component_v_row, { dense: "" }, {
            default: _withCtx$3(() => [
              _createVNode$3(_component_v_col, {
                cols: "12",
                md: "6"
              }, {
                default: _withCtx$3(() => [
                  _createVNode$3(_component_v_text_field, {
                    modelValue: _unref$2(config).cron_string,
                    "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => _unref$2(config).cron_string = $event),
                    label: "执行周期 (Cron 表达式)",
                    variant: "outlined",
                    density: "comfortable",
                    placeholder: "0 */6 * * *",
                    hint: "标准 Cron 表达式格式 (分 时 日 月 周)",
                    "persistent-hint": "",
                    class: "mb-3"
                  }, {
                    "prepend-inner": _withCtx$3(() => [
                      _createVNode$3(_component_v_icon, {
                        color: "info",
                        size: "20"
                      }, {
                        default: _withCtx$3(() => _cache[4] || (_cache[4] = [
                          _createTextVNode$3("mdi-clock-outline")
                        ])),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue"]),
                  _createElementVNode$3("div", _hoisted_1$3, [
                    _cache[5] || (_cache[5] = _createElementVNode$3("span", { class: "text-caption text-medium-emphasis mr-1" }, "快捷预设:", -1)),
                    (_openBlock$3(), _createElementBlock$1(_Fragment, null, _renderList(cronPresets, (preset) => {
                      return _createVNode$3(_component_v_chip, {
                        key: preset.value,
                        size: "x-small",
                        color: "info",
                        variant: "tonal",
                        class: "cursor-pointer font-weight-medium",
                        onClick: ($event) => _unref$2(config).cron_string = preset.value
                      }, {
                        default: _withCtx$3(() => [
                          _createTextVNode$3(_toDisplayString$2(preset.label), 1)
                        ]),
                        _: 2
                      }, 1032, ["onClick"]);
                    }), 64))
                  ])
                ]),
                _: 1
              }),
              _createVNode$3(_component_v_col, {
                cols: "12",
                md: "6"
              }, {
                default: _withCtx$3(() => [
                  _createVNode$3(_component_v_text_field, {
                    modelValue: _unref$2(config).timeout,
                    "onUpdate:modelValue": _cache[1] || (_cache[1] = ($event) => _unref$2(config).timeout = $event),
                    modelModifiers: { number: true },
                    label: "请求超时时间",
                    variant: "outlined",
                    density: "comfortable",
                    type: "number",
                    min: "1",
                    max: "300",
                    suffix: "秒",
                    hint: "网络请求及订阅下载的超时时长",
                    "persistent-hint": "",
                    class: "mb-4",
                    rules: [(v) => v > 0 || "超时时间必须大于 0"]
                  }, {
                    "prepend-inner": _withCtx$3(() => [
                      _createVNode$3(_component_v_icon, {
                        color: "warning",
                        size: "20"
                      }, {
                        default: _withCtx$3(() => _cache[6] || (_cache[6] = [
                          _createTextVNode$3("mdi-timer-sand")
                        ])),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue", "rules"])
                ]),
                _: 1
              }),
              _createVNode$3(_component_v_col, {
                cols: "12",
                md: "6"
              }, {
                default: _withCtx$3(() => [
                  _createVNode$3(_component_v_text_field, {
                    modelValue: _unref$2(config).retry_times,
                    "onUpdate:modelValue": _cache[2] || (_cache[2] = ($event) => _unref$2(config).retry_times = $event),
                    modelModifiers: { number: true },
                    label: "失败重试次数",
                    variant: "outlined",
                    density: "comfortable",
                    type: "number",
                    min: "0",
                    max: "10",
                    hint: "请求失败时的自动重试次数",
                    "persistent-hint": "",
                    rules: [(v) => v >= 0 || "重试次数不能为负数"]
                  }, {
                    "prepend-inner": _withCtx$3(() => [
                      _createVNode$3(_component_v_icon, {
                        color: "info",
                        size: "20"
                      }, {
                        default: _withCtx$3(() => _cache[7] || (_cache[7] = [
                          _createTextVNode$3("mdi-refresh")
                        ])),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue", "rules"])
                ]),
                _: 1
              }),
              _createVNode$3(_component_v_col, {
                cols: "12",
                md: "6"
              }, {
                default: _withCtx$3(() => [
                  _createVNode$3(_component_v_text_field, {
                    modelValue: _unref$2(config).refresh_delay,
                    "onUpdate:modelValue": _cache[3] || (_cache[3] = ($event) => _unref$2(config).refresh_delay = $event),
                    modelModifiers: { number: true },
                    label: "刷新延迟",
                    variant: "outlined",
                    density: "comfortable",
                    type: "number",
                    min: "1",
                    max: "30",
                    suffix: "秒",
                    hint: "通知 Clash 刷新规则集的延迟秒数",
                    "persistent-hint": "",
                    rules: [(v) => v >= 0 || "刷新延迟不能为负数"]
                  }, {
                    "prepend-inner": _withCtx$3(() => [
                      _createVNode$3(_component_v_icon, {
                        color: "primary",
                        size: "20"
                      }, {
                        default: _withCtx$3(() => _cache[8] || (_cache[8] = [
                          _createTextVNode$3("mdi-clock-fast")
                        ])),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue", "rules"])
                ]),
                _: 1
              })
            ]),
            _: 1
          })
        ]),
        _: 1
      });
    };
  }
});

const {defineComponent:_defineComponent$2} = await importShared('vue');

const {createTextVNode:_createTextVNode$2,resolveComponent:_resolveComponent$2,withCtx:_withCtx$2,createVNode:_createVNode$2,createElementVNode:_createElementVNode$2,unref:_unref$1,withModifiers:_withModifiers$1,toDisplayString:_toDisplayString$1,mergeProps:_mergeProps,openBlock:_openBlock$2,createBlock:_createBlock$2} = await importShared('vue');

const _hoisted_1$2 = { class: "d-flex align-center gap-2" };
const _hoisted_2$2 = { class: "d-flex align-center gap-2" };
const {inject} = await importShared('vue');
const _sfc_main$2 = /* @__PURE__ */ _defineComponent$2({
  __name: "AdvancedConfigTab",
  setup(__props) {
    const config = inject("pluginConfig");
    return (_ctx, _cache) => {
      const _component_v_icon = _resolveComponent$2("v-icon");
      const _component_v_switch = _resolveComponent$2("v-switch");
      const _component_v_col = _resolveComponent$2("v-col");
      const _component_v_row = _resolveComponent$2("v-row");
      const _component_v_text_field = _resolveComponent$2("v-text-field");
      const _component_v_chip = _resolveComponent$2("v-chip");
      const _component_v_combobox = _resolveComponent$2("v-combobox");
      const _component_v_card = _resolveComponent$2("v-card");
      return _openBlock$2(), _createBlock$2(_component_v_card, {
        variant: "flat",
        class: "pa-4 border rounded-lg bg-surface"
      }, {
        default: _withCtx$2(() => [
          _createVNode$2(_component_v_row, {
            dense: "",
            class: "mb-4"
          }, {
            default: _withCtx$2(() => [
              _createVNode$2(_component_v_col, {
                cols: "12",
                md: "6"
              }, {
                default: _withCtx$2(() => [
                  _createElementVNode$2("div", {
                    class: "feature-toggle-item d-flex align-center justify-space-between border rounded-lg pa-3 cursor-pointer select-none transition-all",
                    onClick: _cache[2] || (_cache[2] = ($event) => _unref$1(config).hint_geo_dat = !_unref$1(config).hint_geo_dat)
                  }, [
                    _createElementVNode$2("div", _hoisted_1$2, [
                      _createVNode$2(_component_v_icon, {
                        color: "primary",
                        size: "20"
                      }, {
                        default: _withCtx$2(() => _cache[11] || (_cache[11] = [
                          _createTextVNode$2("mdi-database-search-outline")
                        ])),
                        _: 1
                      }),
                      _cache[12] || (_cache[12] = _createElementVNode$2("div", null, [
                        _createElementVNode$2("div", { class: "text-body-2 font-weight-medium" }, "Geo 规则补全"),
                        _createElementVNode$2("div", { class: "text-caption text-medium-emphasis" }, " 自动获取 GeoIP / GeoSite 官方库补全 ")
                      ], -1))
                    ]),
                    _createVNode$2(_component_v_switch, {
                      modelValue: _unref$1(config).hint_geo_dat,
                      "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => _unref$1(config).hint_geo_dat = $event),
                      color: "primary",
                      "hide-details": "",
                      inset: "",
                      density: "compact",
                      onClick: _cache[1] || (_cache[1] = _withModifiers$1(() => {
                      }, ["stop"]))
                    }, null, 8, ["modelValue"])
                  ])
                ]),
                _: 1
              }),
              _createVNode$2(_component_v_col, {
                cols: "12",
                md: "6"
              }, {
                default: _withCtx$2(() => [
                  _createElementVNode$2("div", {
                    class: "feature-toggle-item d-flex align-center justify-space-between border rounded-lg pa-3 cursor-pointer select-none transition-all",
                    onClick: _cache[5] || (_cache[5] = ($event) => _unref$1(config).enable_acl4ssr = !_unref$1(config).enable_acl4ssr)
                  }, [
                    _createElementVNode$2("div", _hoisted_2$2, [
                      _createVNode$2(_component_v_icon, {
                        color: "primary",
                        size: "20"
                      }, {
                        default: _withCtx$2(() => _cache[13] || (_cache[13] = [
                          _createTextVNode$2("mdi-shield-crown-outline")
                        ])),
                        _: 1
                      }),
                      _cache[14] || (_cache[14] = _createElementVNode$2("div", null, [
                        _createElementVNode$2("div", { class: "text-body-2 font-weight-medium" }, "ACL4SSR 规则集"),
                        _createElementVNode$2("div", { class: "text-caption text-medium-emphasis" }, "启用 ACL4SSR 规则集扩展支持")
                      ], -1))
                    ]),
                    _createVNode$2(_component_v_switch, {
                      modelValue: _unref$1(config).enable_acl4ssr,
                      "onUpdate:modelValue": _cache[3] || (_cache[3] = ($event) => _unref$1(config).enable_acl4ssr = $event),
                      color: "primary",
                      "hide-details": "",
                      inset: "",
                      density: "compact",
                      onClick: _cache[4] || (_cache[4] = _withModifiers$1(() => {
                      }, ["stop"]))
                    }, null, 8, ["modelValue"])
                  ])
                ]),
                _: 1
              })
            ]),
            _: 1
          }),
          _createVNode$2(_component_v_row, {
            dense: "",
            class: "mb-2"
          }, {
            default: _withCtx$2(() => [
              _createVNode$2(_component_v_col, {
                cols: "12",
                md: "4"
              }, {
                default: _withCtx$2(() => [
                  _createVNode$2(_component_v_text_field, {
                    modelValue: _unref$1(config).ruleset_prefix,
                    "onUpdate:modelValue": _cache[6] || (_cache[6] = ($event) => _unref$1(config).ruleset_prefix = $event),
                    label: "规则集前缀",
                    variant: "outlined",
                    density: "comfortable",
                    placeholder: "📂<=",
                    hint: "生成规则集名称的前缀标识",
                    "persistent-hint": ""
                  }, {
                    "prepend-inner": _withCtx$2(() => [
                      _createVNode$2(_component_v_icon, {
                        color: "info",
                        size: "20"
                      }, {
                        default: _withCtx$2(() => _cache[15] || (_cache[15] = [
                          _createTextVNode$2("mdi-format-title")
                        ])),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue"])
                ]),
                _: 1
              }),
              _createVNode$2(_component_v_col, {
                cols: "12",
                md: "4"
              }, {
                default: _withCtx$2(() => [
                  _createVNode$2(_component_v_text_field, {
                    modelValue: _unref$1(config).acl4ssr_prefix,
                    "onUpdate:modelValue": _cache[7] || (_cache[7] = ($event) => _unref$1(config).acl4ssr_prefix = $event),
                    label: "ACL4SSR 前缀",
                    variant: "outlined",
                    density: "comfortable",
                    placeholder: "🗂️=>",
                    hint: "ACL4SSR 规则集的前缀标识",
                    "persistent-hint": ""
                  }, {
                    "prepend-inner": _withCtx$2(() => [
                      _createVNode$2(_component_v_icon, {
                        color: "primary",
                        size: "20"
                      }, {
                        default: _withCtx$2(() => _cache[16] || (_cache[16] = [
                          _createTextVNode$2("mdi-tag-outline")
                        ])),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue"])
                ]),
                _: 1
              }),
              _createVNode$2(_component_v_col, {
                cols: "12",
                md: "4"
              }, {
                default: _withCtx$2(() => [
                  _createVNode$2(_component_v_text_field, {
                    modelValue: _unref$1(config).cache_ttl,
                    "onUpdate:modelValue": _cache[8] || (_cache[8] = ($event) => _unref$1(config).cache_ttl = $event),
                    modelModifiers: { number: true },
                    label: "缓存 TTL",
                    variant: "outlined",
                    density: "comfortable",
                    type: "number",
                    min: "600",
                    suffix: "秒",
                    hint: "缓存超时时长",
                    "persistent-hint": ""
                  }, {
                    "prepend-inner": _withCtx$2(() => [
                      _createVNode$2(_component_v_icon, {
                        color: "warning",
                        size: "20"
                      }, {
                        default: _withCtx$2(() => _cache[17] || (_cache[17] = [
                          _createTextVNode$2("mdi-cached")
                        ])),
                        _: 1
                      })
                    ]),
                    _: 1
                  }, 8, ["modelValue"])
                ]),
                _: 1
              })
            ]),
            _: 1
          }),
          _createVNode$2(_component_v_row, { dense: "" }, {
            default: _withCtx$2(() => [
              _createVNode$2(_component_v_col, {
                cols: "12",
                class: "mb-3"
              }, {
                default: _withCtx$2(() => [
                  _createVNode$2(_component_v_combobox, {
                    modelValue: _unref$1(config).best_cf_ip,
                    "onUpdate:modelValue": _cache[9] || (_cache[9] = ($event) => _unref$1(config).best_cf_ip = $event),
                    label: "Cloudflare CDN 优选 IPs",
                    variant: "outlined",
                    density: "comfortable",
                    multiple: "",
                    chips: "",
                    "closable-chips": "",
                    clearable: "",
                    hint: "用于 Hosts 中关联的 Cloudflare CDN 优化 IP",
                    "persistent-hint": "",
                    rules: [_unref$1(validateIPs)]
                  }, {
                    "prepend-inner": _withCtx$2(() => [
                      _createVNode$2(_component_v_icon, {
                        color: "warning",
                        size: "20"
                      }, {
                        default: _withCtx$2(() => _cache[18] || (_cache[18] = [
                          _createTextVNode$2("mdi-cloud-check-outline")
                        ])),
                        _: 1
                      })
                    ]),
                    chip: _withCtx$2(({ props: slotProps, item }) => [
                      _createVNode$2(_component_v_chip, _mergeProps(slotProps, {
                        closable: "",
                        size: "small",
                        color: "warning",
                        variant: "tonal"
                      }), {
                        default: _withCtx$2(() => [
                          _createTextVNode$2(_toDisplayString$1(item.value), 1)
                        ]),
                        _: 2
                      }, 1040)
                    ]),
                    _: 1
                  }, 8, ["modelValue", "rules"])
                ]),
                _: 1
              }),
              _createVNode$2(_component_v_col, { cols: "12" }, {
                default: _withCtx$2(() => [
                  _createVNode$2(_component_v_combobox, {
                    modelValue: _unref$1(config).identifiers,
                    "onUpdate:modelValue": _cache[10] || (_cache[10] = ($event) => _unref$1(config).identifiers = $event),
                    label: "预设设备标识 (Identifiers)",
                    variant: "outlined",
                    density: "comfortable",
                    multiple: "",
                    chips: "",
                    "closable-chips": "",
                    clearable: "",
                    hint: "获取配置时的额外 identifier 查询参数",
                    "persistent-hint": ""
                  }, {
                    "prepend-inner": _withCtx$2(() => [
                      _createVNode$2(_component_v_icon, {
                        color: "info",
                        size: "20"
                      }, {
                        default: _withCtx$2(() => _cache[19] || (_cache[19] = [
                          _createTextVNode$2("mdi-cellphone-link")
                        ])),
                        _: 1
                      })
                    ]),
                    chip: _withCtx$2(({ props: slotProps, item }) => [
                      _createVNode$2(_component_v_chip, _mergeProps(slotProps, {
                        closable: "",
                        size: "small",
                        color: "info",
                        variant: "tonal"
                      }), {
                        default: _withCtx$2(() => [
                          _createTextVNode$2(_toDisplayString$1(item.value), 1)
                        ]),
                        _: 2
                      }, 1040)
                    ]),
                    _: 1
                  }, 8, ["modelValue"])
                ]),
                _: 1
              })
            ]),
            _: 1
          })
        ]),
        _: 1
      });
    };
  }
});

const AdvancedConfigTab = /* @__PURE__ */ _export_sfc(_sfc_main$2, [["__scopeId", "data-v-fe0e1ac0"]]);

const {defineComponent:_defineComponent$1} = await importShared('vue');

const {createTextVNode:_createTextVNode$1,resolveComponent:_resolveComponent$1,withCtx:_withCtx$1,createVNode:_createVNode$1,createElementVNode:_createElementVNode$1,unref:_unref,openBlock:_openBlock$1,createBlock:_createBlock$1} = await importShared('vue');

const _hoisted_1$1 = { class: "d-flex align-center gap-2" };
const _hoisted_2$1 = { class: "ace-editor-wrapper border rounded-lg overflow-hidden mb-3" };
const {ref: ref$1,watch} = await importShared('vue');
const _sfc_main$1 = /* @__PURE__ */ _defineComponent$1({
  __name: "ClashTemplateDialog",
  props: {
    modelValue: { type: Boolean },
    template: {}
  },
  emits: ["update:modelValue", "update:template", "save"],
  setup(__props, { emit: __emit }) {
    const props = __props;
    const emit = __emit;
    const clashTemplateType = ref$1("YAML");
    const clashTemplateContent = ref$1("");
    const editorOptions = {
      enableBasicAutocompletion: true,
      enableSnippets: true,
      enableLiveAutocompletion: true,
      showLineNumbers: true,
      tabSize: 2
    };
    const configPlaceholder = ref$1(
      `profile:
  store-selected: true
mode: rule
log-level: silent`
    );
    watch(
      () => props.modelValue,
      (val) => {
        if (val) {
          clashTemplateContent.value = props.template || "";
        }
      },
      { immediate: true }
    );
    const handleClose = () => {
      emit("update:modelValue", false);
    };
    const handleSave = () => {
      emit("update:template", clashTemplateContent.value);
      emit("save", clashTemplateContent.value);
      emit("update:modelValue", false);
    };
    return (_ctx, _cache) => {
      const _component_v_icon = _resolveComponent$1("v-icon");
      const _component_v_btn = _resolveComponent$1("v-btn");
      const _component_v_card_title = _resolveComponent$1("v-card-title");
      const _component_v_divider = _resolveComponent$1("v-divider");
      const _component_v_select = _resolveComponent$1("v-select");
      const _component_v_alert = _resolveComponent$1("v-alert");
      const _component_v_card_text = _resolveComponent$1("v-card-text");
      const _component_v_spacer = _resolveComponent$1("v-spacer");
      const _component_v_card_actions = _resolveComponent$1("v-card-actions");
      const _component_v_card = _resolveComponent$1("v-card");
      const _component_v_dialog = _resolveComponent$1("v-dialog");
      return _openBlock$1(), _createBlock$1(_component_v_dialog, {
        "model-value": _ctx.modelValue,
        "max-width": "680",
        "onUpdate:modelValue": _cache[2] || (_cache[2] = (val) => emit("update:modelValue", val))
      }, {
        default: _withCtx$1(() => [
          _createVNode$1(_component_v_card, {
            class: "rounded-lg border overflow-hidden",
            elevation: "0"
          }, {
            default: _withCtx$1(() => [
              _createVNode$1(_component_v_card_title, { class: "pa-4 bg-surface d-flex align-center justify-space-between" }, {
                default: _withCtx$1(() => [
                  _createElementVNode$1("div", _hoisted_1$1, [
                    _createVNode$1(_component_v_icon, { color: "primary" }, {
                      default: _withCtx$1(() => _cache[3] || (_cache[3] = [
                        _createTextVNode$1("mdi-file-code-outline")
                      ])),
                      _: 1
                    }),
                    _cache[4] || (_cache[4] = _createElementVNode$1("span", { class: "font-weight-bold text-h6" }, "Clash 配置模板编辑", -1))
                  ]),
                  _createVNode$1(_component_v_btn, {
                    icon: "mdi-close",
                    variant: "text",
                    size: "small",
                    onClick: handleClose
                  })
                ]),
                _: 1
              }),
              _createVNode$1(_component_v_divider),
              _createVNode$1(_component_v_card_text, { class: "pa-4" }, {
                default: _withCtx$1(() => [
                  _createVNode$1(_component_v_select, {
                    modelValue: clashTemplateType.value,
                    "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => clashTemplateType.value = $event),
                    items: ["YAML"],
                    label: "配置格式",
                    variant: "outlined",
                    density: "comfortable",
                    class: "mb-3"
                  }, null, 8, ["modelValue"]),
                  _createElementVNode$1("div", _hoisted_2$1, [
                    _createVNode$1(_unref(VAceEditor), {
                      value: clashTemplateContent.value,
                      "onUpdate:value": _cache[1] || (_cache[1] = ($event) => clashTemplateContent.value = $event),
                      lang: "yaml",
                      theme: "monokai",
                      options: editorOptions,
                      placeholder: configPlaceholder.value,
                      style: { "height": "24rem", "width": "100%" }
                    }, null, 8, ["value", "placeholder"])
                  ]),
                  _createVNode$1(_component_v_alert, {
                    type: "info",
                    variant: "tonal",
                    density: "compact",
                    class: "rounded-lg mb-0"
                  }, {
                    prepend: _withCtx$1(() => [
                      _createVNode$1(_component_v_icon, { size: "18" }, {
                        default: _withCtx$1(() => _cache[5] || (_cache[5] = [
                          _createTextVNode$1("mdi-information-outline")
                        ])),
                        _: 1
                      })
                    ]),
                    default: _withCtx$1(() => [
                      _cache[6] || (_cache[6] = _createElementVNode$1("span", { class: "text-caption" }, "规则与出站代理会自动附加在配置模板之上", -1))
                    ]),
                    _: 1
                  })
                ]),
                _: 1
              }),
              _createVNode$1(_component_v_divider),
              _createVNode$1(_component_v_card_actions, { class: "pa-4 bg-surface" }, {
                default: _withCtx$1(() => [
                  _createVNode$1(_component_v_spacer),
                  _createVNode$1(_component_v_btn, {
                    color: "grey-darken-1",
                    variant: "text",
                    class: "rounded-lg",
                    onClick: handleClose
                  }, {
                    default: _withCtx$1(() => _cache[7] || (_cache[7] = [
                      _createTextVNode$1(" 取消 ")
                    ])),
                    _: 1
                  }),
                  _createVNode$1(_component_v_btn, {
                    color: "primary",
                    variant: "flat",
                    class: "rounded-lg font-weight-bold",
                    onClick: handleSave
                  }, {
                    default: _withCtx$1(() => _cache[8] || (_cache[8] = [
                      _createTextVNode$1(" 保存模板 ")
                    ])),
                    _: 1
                  })
                ]),
                _: 1
              })
            ]),
            _: 1
          })
        ]),
        _: 1
      }, 8, ["model-value"]);
    };
  }
});

const ClashTemplateDialog = /* @__PURE__ */ _export_sfc(_sfc_main$1, [["__scopeId", "data-v-05a8c78c"]]);

const {defineComponent:_defineComponent} = await importShared('vue');

const {createTextVNode:_createTextVNode,resolveComponent:_resolveComponent,withCtx:_withCtx,createVNode:_createVNode,createElementVNode:_createElementVNode,toDisplayString:_toDisplayString,openBlock:_openBlock,createBlock:_createBlock,createCommentVNode:_createCommentVNode,withModifiers:_withModifiers,createElementBlock:_createElementBlock} = await importShared('vue');

const _hoisted_1 = { class: "plugin-config-wrapper" };
const _hoisted_2 = { class: "config-hero-header pa-4 pa-md-5 d-flex flex-wrap align-center justify-space-between gap-4" };
const _hoisted_3 = { class: "d-flex align-center gap-3" };
const _hoisted_4 = { class: "hero-icon-avatar rounded-lg d-flex align-center justify-center" };
const _hoisted_5 = { class: "d-flex align-center gap-2" };
const _hoisted_6 = { class: "d-flex align-center gap-2" };
const _hoisted_7 = { class: "font-weight-medium" };
const _hoisted_8 = { class: "tabs-container mb-4" };
const _hoisted_9 = { class: "pa-4 bg-surface d-flex flex-wrap align-center justify-space-between gap-3" };
const _hoisted_10 = { class: "d-flex align-center text-caption text-medium-emphasis" };
const _hoisted_11 = {
  href: "https://github.com/wumode/MoviePilot-Plugins/tree/main/plugins.v2/clashruleprovider/README.md",
  target: "_blank",
  class: "text-primary font-weight-bold text-decoration-none ml-1"
};
const _hoisted_12 = { class: "d-flex align-center gap-2" };
const {ref,reactive,onMounted,computed,provide} = await importShared('vue');
const _sfc_main = /* @__PURE__ */ _defineComponent({
  __name: "Config",
  props: {
    initialConfig: {
      type: Object,
      default: () => ({})
    },
    api: {
      type: Object,
      default: () => {
      }
    }
  },
  emits: ["save", "close", "switch"],
  setup(__props, { emit: __emit }) {
    const props = __props;
    const emit = __emit;
    const toast = useToast();
    const activeTab = ref("subscription");
    const clashTemplateDialog = ref(false);
    const form = ref(null);
    const isFormValid = ref(true);
    const error = ref("");
    const saving = ref(false);
    const testing = ref(false);
    const defaultConfig = {
      enabled: false,
      subscriptions_config: [],
      filter_keywords: ["公益性", "高延迟", "域名", "官网", "重启", "过期时间", "系统代理"],
      clash_dashboards: [{ url: "", secret: "" }],
      movie_pilot_url: "",
      cron_string: "0 */6 * * *",
      timeout: 10,
      retry_times: 3,
      proxy: false,
      notify: false,
      auto_update_subscriptions: true,
      ruleset_prefix: "📂<=",
      acl4ssr_prefix: "🗂️=>",
      group_by_region: false,
      group_by_country: false,
      refresh_delay: 5,
      enable_acl4ssr: false,
      dashboard_components: [],
      clash_template: "",
      hint_geo_dat: false,
      best_cf_ip: [],
      active_dashboard: 0,
      apikey: null,
      identifiers: [],
      cache_ttl: 3600
    };
    const config = reactive({ ...defaultConfig });
    provide("pluginConfig", config);
    onMounted(() => {
      if (props.initialConfig) {
        Object.keys(props.initialConfig).forEach((key) => {
          if (key in config) {
            config[key] = props.initialConfig[key];
          }
        });
      }
    });
    const sub_links = computed(() => {
      if (!config.subscriptions_config) {
        return [];
      }
      return config.subscriptions_config.map((item) => item.url);
    });
    async function testConnection() {
      testing.value = true;
      error.value = "";
      try {
        if (sub_links.value.length === 0) {
          toast.error("请先配置至少一个订阅链接");
          return;
        }
        const testParams = {
          clash_apis: config.clash_dashboards,
          sub_links: sub_links.value
        };
        const result = await props.api.post("/plugin/ClashRuleProvider/connectivity", testParams);
        if (result.success) {
          toast.success("连接测试成功！Clash 面板和订阅链接连接正常，配置验证通过");
        } else {
          toast.error(result.message || "连接测试失败，请检查配置");
        }
      } catch (err) {
        if (err instanceof Error) toast.error(err.message || "连接测试失败");
      } finally {
        testing.value = false;
      }
    }
    async function saveConfig() {
      for (let i = 0; i < config.subscriptions_config.length; i++) {
        const sub = config.subscriptions_config[i];
        if (!sub.url || !isValidUrl(sub.url)) {
          error.value = `订阅配置 ${i + 1} 中的 URL 无效或为空`;
          toast.error(error.value);
          return;
        }
      }
      if (!isFormValid.value) {
        error.value = "请修正表单中的错误";
        toast.error(error.value);
        return;
      }
      saving.value = true;
      error.value = "";
      try {
        await new Promise((resolve) => setTimeout(resolve, 800));
        emit("save", { ...config });
      } catch (err) {
        if (err instanceof Error) {
          error.value = err.message || "保存配置失败";
          toast.error(error.value);
        }
      } finally {
        saving.value = false;
      }
    }
    function resetForm() {
      Object.assign(config, JSON.parse(JSON.stringify(defaultConfig)));
      if (form.value) {
        form.value.resetValidation();
      }
    }
    return (_ctx, _cache) => {
      const _component_v_icon = _resolveComponent("v-icon");
      const _component_v_chip = _resolveComponent("v-chip");
      const _component_v_btn = _resolveComponent("v-btn");
      const _component_v_divider = _resolveComponent("v-divider");
      const _component_v_alert = _resolveComponent("v-alert");
      const _component_v_badge = _resolveComponent("v-badge");
      const _component_v_tab = _resolveComponent("v-tab");
      const _component_v_tabs = _resolveComponent("v-tabs");
      const _component_v_window_item = _resolveComponent("v-window-item");
      const _component_v_window = _resolveComponent("v-window");
      const _component_v_form = _resolveComponent("v-form");
      const _component_v_card_text = _resolveComponent("v-card-text");
      const _component_v_card = _resolveComponent("v-card");
      return _openBlock(), _createElementBlock("div", _hoisted_1, [
        _createVNode(_component_v_card, {
          class: "modern-config-card border rounded-lg overflow-hidden",
          elevation: "0"
        }, {
          default: _withCtx(() => [
            _createElementVNode("div", _hoisted_2, [
              _createElementVNode("div", _hoisted_3, [
                _createElementVNode("div", _hoisted_4, [
                  _createVNode(_component_v_icon, {
                    size: "24",
                    color: "primary"
                  }, {
                    default: _withCtx(() => _cache[9] || (_cache[9] = [
                      _createTextVNode("mdi-tune-variant")
                    ])),
                    _: 1
                  })
                ]),
                _createElementVNode("div", null, [
                  _createElementVNode("div", _hoisted_5, [
                    _cache[10] || (_cache[10] = _createElementVNode("h2", { class: "text-h6 font-weight-bold text-high-emphasis" }, "Clash Rule Provider", -1)),
                    _createVNode(_component_v_chip, {
                      color: config.enabled ? "success" : "grey",
                      size: "small",
                      variant: "tonal",
                      class: "font-weight-medium ml-2"
                    }, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_icon, {
                          start: "",
                          size: "14"
                        }, {
                          default: _withCtx(() => [
                            _createTextVNode(_toDisplayString(config.enabled ? "mdi-check-circle" : "mdi-pause-circle"), 1)
                          ]),
                          _: 1
                        }),
                        _createTextVNode(" " + _toDisplayString(config.enabled ? "已启用" : "未启用"), 1)
                      ]),
                      _: 1
                    }, 8, ["color"])
                  ])
                ])
              ]),
              _createElementVNode("div", _hoisted_6, [
                _createVNode(_component_v_btn, {
                  color: "primary",
                  variant: "tonal",
                  size: "small",
                  class: "rounded-lg text-none",
                  onClick: _cache[0] || (_cache[0] = ($event) => emit("switch"))
                }, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_icon, { start: "" }, {
                      default: _withCtx(() => _cache[11] || (_cache[11] = [
                        _createTextVNode("mdi-view-dashboard-edit")
                      ])),
                      _: 1
                    }),
                    _cache[12] || (_cache[12] = _createTextVNode(" 切换至规则 "))
                  ]),
                  _: 1
                }),
                _createVNode(_component_v_btn, {
                  icon: "",
                  variant: "text",
                  color: "grey-darken-1",
                  density: "comfortable",
                  onClick: _cache[1] || (_cache[1] = ($event) => emit("close"))
                }, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_icon, null, {
                      default: _withCtx(() => _cache[13] || (_cache[13] = [
                        _createTextVNode("mdi-close")
                      ])),
                      _: 1
                    })
                  ]),
                  _: 1
                })
              ])
            ]),
            _createVNode(_component_v_divider),
            _createVNode(_component_v_card_text, { class: "pa-4 pa-md-6" }, {
              default: _withCtx(() => [
                error.value ? (_openBlock(), _createBlock(_component_v_alert, {
                  key: 0,
                  type: "error",
                  variant: "tonal",
                  closable: "",
                  class: "mb-6 rounded-lg border-error",
                  "onClick:close": _cache[2] || (_cache[2] = ($event) => error.value = "")
                }, {
                  prepend: _withCtx(() => [
                    _createVNode(_component_v_icon, { color: "error" }, {
                      default: _withCtx(() => _cache[14] || (_cache[14] = [
                        _createTextVNode("mdi-alert-circle")
                      ])),
                      _: 1
                    })
                  ]),
                  default: _withCtx(() => [
                    _createElementVNode("span", _hoisted_7, _toDisplayString(error.value), 1)
                  ]),
                  _: 1
                })) : _createCommentVNode("", true),
                _createVNode(_component_v_form, {
                  ref_key: "form",
                  ref: form,
                  modelValue: isFormValid.value,
                  "onUpdate:modelValue": _cache[6] || (_cache[6] = ($event) => isFormValid.value = $event),
                  onSubmit: _withModifiers(saveConfig, ["prevent"])
                }, {
                  default: _withCtx(() => [
                    _createVNode(MasterSwitches),
                    _createVNode(BasicConfigSection),
                    _createElementVNode("div", _hoisted_8, [
                      _createVNode(_component_v_tabs, {
                        modelValue: activeTab.value,
                        "onUpdate:modelValue": _cache[3] || (_cache[3] = ($event) => activeTab.value = $event),
                        color: "primary",
                        "align-tabs": "start",
                        class: "custom-modern-tabs"
                      }, {
                        default: _withCtx(() => [
                          _createVNode(_component_v_tab, {
                            value: "subscription",
                            class: "rounded-lg text-none px-4 py-2 font-weight-bold"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                start: "",
                                size: "18"
                              }, {
                                default: _withCtx(() => _cache[15] || (_cache[15] = [
                                  _createTextVNode("mdi-link-variant")
                                ])),
                                _: 1
                              }),
                              _cache[16] || (_cache[16] = _createTextVNode(" 订阅配置 ")),
                              config.subscriptions_config?.length ? (_openBlock(), _createBlock(_component_v_badge, {
                                key: 0,
                                content: config.subscriptions_config.length,
                                color: "primary",
                                inline: "",
                                class: "ml-2"
                              }, null, 8, ["content"])) : _createCommentVNode("", true)
                            ]),
                            _: 1
                          }),
                          _createVNode(_component_v_tab, {
                            value: "clash",
                            class: "rounded-lg text-none px-4 py-2 font-weight-bold"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                start: "",
                                size: "18"
                              }, {
                                default: _withCtx(() => _cache[17] || (_cache[17] = [
                                  _createTextVNode("mdi-application-brackets-outline")
                                ])),
                                _: 1
                              }),
                              _cache[18] || (_cache[18] = _createTextVNode(" Clash API 配置 ")),
                              config.clash_dashboards?.length ? (_openBlock(), _createBlock(_component_v_badge, {
                                key: 0,
                                content: config.clash_dashboards.length,
                                color: "info",
                                inline: "",
                                class: "ml-2"
                              }, null, 8, ["content"])) : _createCommentVNode("", true)
                            ]),
                            _: 1
                          }),
                          _createVNode(_component_v_tab, {
                            value: "execution",
                            class: "rounded-lg text-none px-4 py-2 font-weight-bold"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                start: "",
                                size: "18"
                              }, {
                                default: _withCtx(() => _cache[19] || (_cache[19] = [
                                  _createTextVNode("mdi-clock-time-four-outline")
                                ])),
                                _: 1
                              }),
                              _cache[20] || (_cache[20] = _createTextVNode(" 执行与定时 "))
                            ]),
                            _: 1
                          }),
                          _createVNode(_component_v_tab, {
                            value: "settings",
                            class: "rounded-lg text-none px-4 py-2 font-weight-bold"
                          }, {
                            default: _withCtx(() => [
                              _createVNode(_component_v_icon, {
                                start: "",
                                size: "18"
                              }, {
                                default: _withCtx(() => _cache[21] || (_cache[21] = [
                                  _createTextVNode("mdi-tune")
                                ])),
                                _: 1
                              }),
                              _cache[22] || (_cache[22] = _createTextVNode(" 高级与规则集 "))
                            ]),
                            _: 1
                          })
                        ]),
                        _: 1
                      }, 8, ["modelValue"])
                    ]),
                    _createVNode(_component_v_window, {
                      modelValue: activeTab.value,
                      "onUpdate:modelValue": _cache[5] || (_cache[5] = ($event) => activeTab.value = $event),
                      class: "tab-window-content"
                    }, {
                      default: _withCtx(() => [
                        _createVNode(_component_v_window_item, { value: "subscription" }, {
                          default: _withCtx(() => [
                            _createVNode(SubscriptionConfigTab, {
                              onOpenTemplate: _cache[4] || (_cache[4] = ($event) => clashTemplateDialog.value = true)
                            })
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_window_item, { value: "clash" }, {
                          default: _withCtx(() => [
                            _createVNode(ClashApiConfigTab)
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_window_item, { value: "execution" }, {
                          default: _withCtx(() => [
                            _createVNode(_sfc_main$3)
                          ]),
                          _: 1
                        }),
                        _createVNode(_component_v_window_item, { value: "settings" }, {
                          default: _withCtx(() => [
                            _createVNode(AdvancedConfigTab)
                          ]),
                          _: 1
                        })
                      ]),
                      _: 1
                    }, 8, ["modelValue"])
                  ]),
                  _: 1
                }, 8, ["modelValue"])
              ]),
              _: 1
            }),
            _createVNode(_component_v_divider),
            _createElementVNode("div", _hoisted_9, [
              _createElementVNode("div", _hoisted_10, [
                _createVNode(_component_v_icon, {
                  color: "info",
                  size: "18",
                  class: "mr-1"
                }, {
                  default: _withCtx(() => _cache[23] || (_cache[23] = [
                    _createTextVNode("mdi-help-circle-outline")
                  ])),
                  _: 1
                }),
                _cache[26] || (_cache[26] = _createTextVNode(" 配置文档参考: ")),
                _createElementVNode("a", _hoisted_11, [
                  _cache[25] || (_cache[25] = _createTextVNode(" GitHub README ")),
                  _createVNode(_component_v_icon, { size: "12" }, {
                    default: _withCtx(() => _cache[24] || (_cache[24] = [
                      _createTextVNode("mdi-open-in-new")
                    ])),
                    _: 1
                  })
                ])
              ]),
              _createElementVNode("div", _hoisted_12, [
                _createVNode(_component_v_btn, {
                  color: "grey-darken-1",
                  variant: "outlined",
                  size: "small",
                  class: "rounded-lg text-none",
                  onClick: resetForm
                }, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_icon, { start: "" }, {
                      default: _withCtx(() => _cache[27] || (_cache[27] = [
                        _createTextVNode("mdi-refresh")
                      ])),
                      _: 1
                    }),
                    _cache[28] || (_cache[28] = _createTextVNode(" 重置 "))
                  ]),
                  _: 1
                }),
                _createVNode(_component_v_btn, {
                  color: "info",
                  variant: "tonal",
                  size: "small",
                  class: "rounded-lg text-none",
                  loading: testing.value,
                  onClick: testConnection
                }, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_icon, { start: "" }, {
                      default: _withCtx(() => _cache[29] || (_cache[29] = [
                        _createTextVNode("mdi-lan-check")
                      ])),
                      _: 1
                    }),
                    _cache[30] || (_cache[30] = _createTextVNode(" 测试连接 "))
                  ]),
                  _: 1
                }, 8, ["loading"]),
                _createVNode(_component_v_btn, {
                  color: "primary",
                  variant: "flat",
                  size: "small",
                  class: "rounded-lg text-none font-weight-bold px-4",
                  disabled: !isFormValid.value,
                  loading: saving.value,
                  onClick: saveConfig
                }, {
                  default: _withCtx(() => [
                    _createVNode(_component_v_icon, { start: "" }, {
                      default: _withCtx(() => _cache[31] || (_cache[31] = [
                        _createTextVNode("mdi-content-save-outline")
                      ])),
                      _: 1
                    }),
                    _cache[32] || (_cache[32] = _createTextVNode(" 保存配置 "))
                  ]),
                  _: 1
                }, 8, ["disabled", "loading"])
              ])
            ])
          ]),
          _: 1
        }),
        _createVNode(ClashTemplateDialog, {
          modelValue: clashTemplateDialog.value,
          "onUpdate:modelValue": _cache[7] || (_cache[7] = ($event) => clashTemplateDialog.value = $event),
          template: config.clash_template,
          "onUpdate:template": _cache[8] || (_cache[8] = ($event) => config.clash_template = $event)
        }, null, 8, ["modelValue", "template"])
      ]);
    };
  }
});

const ConfigComponent = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-e0689a8b"]]);

export { ConfigComponent as default };
