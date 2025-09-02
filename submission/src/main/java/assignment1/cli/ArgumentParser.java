package assignment1.cli;

public class ArgumentParser {

    public static ArgumentBundle parse(String[] args) {
        if (args.length < 2) {
            System.err.println("Error: Not enough arguments.");
            return null;
        }

        ArgumentBundle bundle = new ArgumentBundle();

        // Operation
        String op = args[0].toLowerCase();
        if (op.equals("enc")) {
            bundle.setOperation(ArgumentBundle.Operation.ENCRYPT);
        } else if (op.equals("dec")) {
            bundle.setOperation(ArgumentBundle.Operation.DECRYPT);
        } else {
            System.err.println("Error: First argument must be 'enc' or 'dec'.");
            return null;
        }

        // Parse flags
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];

            if (arg.equals("-in")) {
                if (++i >= args.length) { System.err.println("Error: Missing input file"); return null; }
                bundle.setInputFile(args[i]);
            }
            else if (arg.equals("-out")) {
                if (++i >= args.length) { System.err.println("Error: Missing value for -out"); return null; }
                bundle.setOutputFile(args[i]);
            }
            else if (arg.equals("-pass")) {
                if (++i >= args.length) { System.err.println("Error: Missing value for -pass"); return null; }
                bundle.setPassword(args[i]);
            }
            else if (arg.equals("-salt")) {
                if (++i >= args.length) { System.err.println("Error: Missing value for -salt"); return null; }
                bundle.setSaltFile(args[i]);
            }
            else if (arg.equals("-key")) {
                if (++i >= args.length) { System.err.println("Error: Missing value for -key"); return null; }
                bundle.setKeyFile(args[i]);
            }
            else if (arg.equals("-iv")) {
                if (++i >= args.length) { System.err.println("Error: Missing value for -iv"); return null; }
                bundle.setIvFile(args[i]);
            }
            else if (arg.equals("-cipher")) {
                if (++i >= args.length) { System.err.println("Error: Missing value for -cipher"); return null; }
                bundle.setCipherSpec(args[i].toLowerCase());
            }
            else {
                System.err.println("Error: Unknown argument: " + arg);
                return null;
            }
        }

        return bundle;
    }
}
