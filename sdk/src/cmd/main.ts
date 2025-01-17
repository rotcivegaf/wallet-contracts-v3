import cac from 'cac'

const cli = cac('sequence-fuego')

cli.command('encode-message <message>', 'Encode message').action((message) => {
  console.log('message:', message)
})

cli.on('command:*', () => {
  console.error('Command not found')
  cli.outputHelp()
  process.exit(1)
})

cli.help()
cli.version('0.0.1')

cli.parse()
