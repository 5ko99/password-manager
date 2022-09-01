use password_manager::program;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut program = program::Program::default();
    program.run()
}
