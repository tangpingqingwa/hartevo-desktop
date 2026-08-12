import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

guard CommandLine.arguments.count == 7 else {
    FileHandle.standardError.write(
        Data("usage: crop-image input output x y width height\n".utf8)
    )
    exit(64)
}

let input = URL(fileURLWithPath: CommandLine.arguments[1])
let output = URL(fileURLWithPath: CommandLine.arguments[2])
let values = CommandLine.arguments[3...].compactMap(Int.init)
guard values.count == 4,
      let source = CGImageSourceCreateWithURL(input as CFURL, nil),
      let image = CGImageSourceCreateImageAtIndex(source, 0, nil)
else {
    FileHandle.standardError.write(Data("unable to read crop input\n".utf8))
    exit(65)
}

let rect = CGRect(x: values[0], y: values[1], width: values[2], height: values[3])
guard let cropped = image.cropping(to: rect),
      let destination = CGImageDestinationCreateWithURL(
          output as CFURL,
          UTType.png.identifier as CFString,
          1,
          nil
      )
else {
    FileHandle.standardError.write(Data("unable to crop image\n".utf8))
    exit(66)
}

CGImageDestinationAddImage(destination, cropped, nil)
guard CGImageDestinationFinalize(destination) else {
    FileHandle.standardError.write(Data("unable to write crop output\n".utf8))
    exit(67)
}
