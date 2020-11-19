# src/utils/state_machine.h
define SM_STEP(machine)				定义方法
	static void sm_ ## machine ## _Step(STATE_MACHINE_DATA *sm)

define SM_STEP_RUN(machine)		调用方法
	sm_ ## machine ## _Step(sm)


define SM_STATE(machine, state)		定义方法
	static void sm_ ## machine ## _ ## state ## _Enter(STATE_MACHINE_DATA *sm, int global)


define SM_ENTER(machine, state)		调用方法
	sm_ ## machine ## _ ## state ## _Enter(sm, 0)


define SM_ENTRY(machine, state)		设置状态机当前状态
	sm->machine ## _state = machine ## _ ## state;