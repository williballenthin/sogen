#pragma once
#include "cpu_gdb_stub_handler.hpp"
#include "windows_filesystem.hpp"

#include <atomic>
#include <windows_emulator.hpp>
#include <thread_context.hpp>
#include <segment_utils.hpp>
#include <utils/function.hpp>
#include <utils/string.hpp>

namespace sogen
{

    enum class gdb_target_architecture
    {
        automatic,
        bits_64,
        bits_32,
    };

    class win_gdb_stub_handler : public cpu_gdb_stub_handler
    {
      public:
        win_gdb_stub_handler(windows_emulator& win_emu, utils::optional_function<bool()> should_stop = {},
                             const gdb_target_architecture target_architecture = gdb_target_architecture::bits_64)
            : cpu_gdb_stub_handler(win_emu.emu()),
              win_emu_(&win_emu),
              should_stop_(std::move(should_stop)),
              windows_filesystem_(win_emu),
              target_architecture_(target_architecture)
        {
            auto hook = [this](mapped_module& mod) {
                if (!this->is_visible_module(mod))
                {
                    return;
                }

                library_stop_pending_ = true;
                win_emu_->stop();
            };

            mod_load_id = win_emu_->callbacks.on_module_load.add(hook);
            mod_unload_id = win_emu_->callbacks.on_module_unload.add(hook);
            dbg_msg_id = win_emu_->callbacks.on_debug_string.add([this](std::string_view message) {
                debug_message.assign(message);
                action = gdb_stub::action::output;
                win_emu_->stop();
            });
        }

        ~win_gdb_stub_handler() override
        {
            win_emu_->callbacks.on_module_load.remove(mod_load_id);
            win_emu_->callbacks.on_module_unload.remove(mod_unload_id);
            win_emu_->callbacks.on_debug_string.remove(dbg_msg_id);
        }

        void on_interrupt() override
        {
            this->win_emu_->stop();
        }

        bool should_stop() override
        {
            return this->should_stop_();
        }

        gdb_stub::action run() override
        {
            try
            {
                this->win_emu_->start();
            }
            catch (const std::exception& e)
            {
                this->win_emu_->log.error("%s\n", e.what());
            }

            return action;
        }

        gdb_stub::action singlestep() override
        {
            try
            {
                auto& vcpu = this->win_emu_->vcpu(0);

                // Bypass the emulator scheduler: the GDB protocol already
                // selected the target thread via switch_to_thread(). Going
                // through windows_emulator::start() would let the scheduler
                // redirect to a different "ready" thread (e.g. when the
                // stepped thread is in NtDelayExecution), causing IDA to
                // receive a T05 for an unexpected tid → SIGTRAP error.
                vcpu.switch_thread = false;
                vcpu.thread().setup_if_necessary(vcpu.cpu, this->win_emu_->process);
                vcpu.cpu.start(1);

                for (size_t i = 0;
                     this->wow64_view() && !this->runs_x86_code() && action == gdb_stub::action::resume && i < max_native_steps; ++i)
                {
                    vcpu.cpu.start(1);
                }
            }
            catch (const std::exception& e)
            {
                this->win_emu_->log.error("%s\n", e.what());
            }

            return action;
        }

        uint32_t get_current_thread_id() override
        {
            return this->win_emu_->current_thread().id;
        }

        std::vector<uint32_t> get_thread_ids() override
        {
            const auto& threads = this->win_emu_->process.threads;

            std::vector<uint32_t> ids{};
            ids.reserve(threads.size());

            for (const auto& t : threads | std::views::values)
            {
                if (!t.is_terminated())
                {
                    ids.push_back(t.id);
                }
            }

            return ids;
        }

        bool switch_to_thread(const uint32_t thread_id) override
        {
            return this->win_emu_->activate_thread(this->win_emu_->vcpu(0), thread_id);
        }

        std::optional<uint32_t> get_exit_code() override
        {
            const auto status = this->win_emu_->process.exit_status;
            if (!status)
            {
                return std::nullopt;
            }

            return static_cast<uint32_t>(*status);
        }

        std::vector<gdb_stub::library_info> get_libraries() override
        {
            std::vector<gdb_stub::library_info> libs{};
            const auto& mod_manager = this->win_emu_->mod_manager;
            libs.reserve(this->win_emu_->mod_manager.modules().size());
            for (const auto& [base_addr, mod] : mod_manager.modules())
            {
                if (!mod.module_path.empty() && this->is_visible_module(mod))
                {
                    libs.push_back({.name = mod.module_path.string(), .segment_address = base_addr + 0x1000});
                }
            }

            return libs;
        }

        std::string get_executable_path() override
        {
            const auto& mod_manager = this->win_emu_->mod_manager;
            return mod_manager.executable->module_path.string();
        }

        void reset_library_stop() override
        {
            library_stop_pending_ = false;
        }

        bool should_signal_library() override
        {
            return library_stop_pending_;
        }

        std::vector<gdb_stub::thread_info> get_thread_list() const override
        {
            std::vector<gdb_stub::thread_info> thread_list{};
            const auto& threads = this->win_emu_->process.threads;
            thread_list.reserve(threads.size());

            for (const auto& t : threads | std::views::values)
            {
                if (!t.is_terminated())
                {
                    thread_list.push_back({.id = t.id, .name = u16_to_u8(t.name)});
                }
            }

            return thread_list;
        }

        uint64_t get_thread_teb_addr(uint32_t id) const override
        {
            for (const auto& t : this->win_emu_->process.threads | std::views::values)
            {
                if (t.id == id)
                {
                    if (!t.is_terminated() && this->wow64_view() && t.teb32)
                    {
                        return t.teb32->value();
                    }

                    if (!t.is_terminated() && t.teb64)
                    {
                        return t.teb64->value();
                    }

                    break;
                }
            }

            return 0;
        }

        std::string consume_debug_output() override
        {
            action = gdb_stub::action::resume;
            return std::exchange(debug_message, std::string{});
        }

        std::string get_os_abi() override
        {
            return "Windows";
        }

        bool is_32_bit() const override
        {
            switch (target_architecture_)
            {
            case gdb_target_architecture::automatic:
                return win_emu_->process.is_wow64_process;
            case gdb_target_architecture::bits_32:
                return true;
            case gdb_target_architecture::bits_64:
                return false;
            }

            throw std::runtime_error("Invalid GDB target architecture");
        }

        gdb_stub::filesystem_interface* get_filesystem() override
        {
            return &windows_filesystem_;
        }

        static uint32_t* wow64_context_field(WOW64_CONTEXT& c, const size_t reg)
        {
            const std::array<uint32_t*, 16> fields{
                &c.Eax, &c.Ecx,    &c.Edx,   &c.Ebx,   &c.Esp,   &c.Ebp,   &c.Esi,   &c.Edi,
                &c.Eip, &c.EFlags, &c.SegCs, &c.SegSs, &c.SegDs, &c.SegEs, &c.SegFs, &c.SegGs,
            };
            return reg < fields.size() ? fields[reg] : nullptr;
        }

        size_t read_register(const size_t reg, void* data, const size_t max_length) override
        {
            if (!this->wow64_view() || this->runs_x86_code() || max_length < 4)
            {
                return cpu_gdb_stub_handler::read_register(reg, data, max_length);
            }

            if (reg == fs_base_index)
            {
                const uint32_t value = static_cast<uint32_t>(this->get_thread_teb_addr(this->get_current_thread_id()));
                memcpy(data, &value, sizeof(value));
                return sizeof(value);
            }

            auto context = this->read_wow64_context();
            const auto* field = context ? wow64_context_field(*context, reg) : nullptr;
            if (!field)
            {
                return cpu_gdb_stub_handler::read_register(reg, data, max_length);
            }

            memcpy(data, field, sizeof(uint32_t));
            return sizeof(uint32_t);
        }

        size_t write_register(const size_t reg, const void* data, const size_t size) override
        {
            if (!this->wow64_view() || this->runs_x86_code() || size < 4)
            {
                return cpu_gdb_stub_handler::write_register(reg, data, size);
            }

            auto context = this->read_wow64_context();
            auto* field = context ? wow64_context_field(*context, reg) : nullptr;
            if (!field)
            {
                return cpu_gdb_stub_handler::write_register(reg, data, size);
            }

            memcpy(field, data, sizeof(uint32_t));
            context->ContextFlags = CONTEXT_CONTROL_32 | CONTEXT_INTEGER_32 | CONTEXT_SEGMENTS_32;

            auto& vcpu = this->win_emu_->vcpu(0);
            const auto* bytes = reinterpret_cast<const uint8_t*>(&*context);
            if (!apply_wow64_thread_context(*this->win_emu_, vcpu, vcpu.thread(), {bytes, sizeof(WOW64_CONTEXT)}))
            {
                return 0;
            }

            return sizeof(uint32_t);
        }

      private:
        static constexpr size_t max_native_steps = 1'000'000;
        static constexpr size_t fs_base_index = 41;

        bool wow64_view() const
        {
            return this->is_32_bit() && this->win_emu_->process.is_wow64_process;
        }

        bool runs_x86_code() const
        {
            auto& cpu = this->win_emu_->vcpu(0).x64_cpu();
            const auto bitness = segment_utils::get_segment_bitness(cpu, cpu.reg<uint16_t>(x86_register::cs));
            return bitness && *bitness == segment_utils::segment_bitness::bit32;
        }

        bool is_visible_module(const mapped_module& mod) const
        {
            return !this->wow64_view() || mod.machine == static_cast<uint16_t>(PEMachineType::I386);
        }

        std::optional<WOW64_CONTEXT> read_wow64_context() const
        {
            auto& vcpu = this->win_emu_->vcpu(0);
            const auto bytes = capture_wow64_thread_context(*this->win_emu_, vcpu, vcpu.thread());
            if (bytes.size() < sizeof(WOW64_CONTEXT))
            {
                return std::nullopt;
            }

            WOW64_CONTEXT context{};
            memcpy(&context, bytes.data(), sizeof(context));
            return context;
        }

        windows_emulator* win_emu_{};
        utils::optional_function<bool()> should_stop_{};
        windows_filesystem windows_filesystem_;
        gdb_target_architecture target_architecture_{gdb_target_architecture::bits_64};

        // Track library stop events
        std::atomic<bool> library_stop_pending_{true};
        std::string debug_message{};
        gdb_stub::action action{gdb_stub::action::resume};
        utils::callback_id_type mod_load_id{};
        utils::callback_id_type mod_unload_id{};
        utils::callback_id_type dbg_msg_id{};
    };

} // namespace sogen
